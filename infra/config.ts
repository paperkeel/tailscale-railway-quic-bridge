import { isIP } from "node:net";

import type { TailbridgeArgs, TailbridgeConnectorTarget } from "./tailbridge";

export type SSTHome = "cloudflare" | "local";

export interface NormalizedConnectorTarget extends TailbridgeConnectorTarget {
	region: string;
	realPrefix: string;
	virtualPrefix: string;
	dnsSuffix: string;
	nameserver: string;
}

export interface NormalizedTailbridgeArgs
	extends Omit<TailbridgeArgs, "connectors"> {
	virtualNetwork: string;
	connectors: NormalizedConnectorTarget[];
}

const namePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const defaultVirtualNetwork = "fd20::/11";
const defaultRealPrefix = "fd12::/16";
const defaultRailwayRegion = "us-west2";

export function parseHome(value: string | undefined): SSTHome {
	const home = value?.trim() || "cloudflare";
	if (home !== "cloudflare" && home !== "local") {
		throw new Error("SST_HOME must be cloudflare or local.");
	}
	return home;
}

export function normalizeTailbridgeArgs(
	args: TailbridgeArgs,
): NormalizedTailbridgeArgs {
	validateName("stage", args.stage);
	validateName("edgeId", args.edgeId);
	if (args.edge.provider !== "digitalocean") {
		throw new Error("edge.provider must be digitalocean.");
	}
	if (!args.edge.region.trim() || !args.edge.size.trim()) {
		throw new Error("edge.region and edge.size must not be empty.");
	}
	if (args.edge.sshSourceCidrs.length === 0) {
		throw new Error("edge.sshSourceCidrs must contain at least one CIDR.");
	}
	for (const cidr of args.edge.sshSourceCidrs) {
		validateCidr("edge.sshSourceCidrs", cidr);
	}
	const connectors = args.connectors ?? [];
	if (!args.registration && connectors.length === 0) {
		throw new Error(
			"connectors must contain at least one target when registration is not configured.",
		);
	}
	if (connectors.length > 32) {
		throw new Error("connectors must contain between 1 and 32 targets.");
	}

	const requestedVirtualNetwork =
		args.registration?.virtualNetwork ??
		args.virtualNetwork ??
		(args.registration ? "fd40::/10" : defaultVirtualNetwork);
	if (args.registration) {
		validateDynamicNetwork(
			requestedVirtualNetwork,
			args.registration.excludedPrefixes ?? [defaultRealPrefix],
		);
	}
	const networkLength = args.registration
		? Number(requestedVirtualNetwork.split("/")[1])
		: 11;
	const virtualBase = parseIpv6Prefix(
		requestedVirtualNetwork,
		networkLength,
		"virtualNetwork",
	);
	const virtualNetwork = formatIpv6Prefix(virtualBase, networkLength);
	const names = new Set<string>();
	const slots = new Set<number>();
	const normalizedConnectors = connectors.map((target) => {
		validateTarget(target);
		if (args.registration && target.slot >= 2 ** (16 - networkLength)) {
			throw new Error(
				`connector ${target.name} slot does not fit registration.virtualNetwork.`,
			);
		}
		if (names.has(target.name)) {
			throw new Error(`connector name ${target.name} must be unique.`);
		}
		if (slots.has(target.slot)) {
			throw new Error(`connector slot ${target.slot} must be unique.`);
		}
		names.add(target.name);
		slots.add(target.slot);

		const realPrefix = target.realPrefix ?? defaultRealPrefix;
		parseIpv6Prefix(realPrefix, 16, `connector ${target.name} realPrefix`);
		const virtualPrefix = formatIpv6Prefix(
			virtualBase | (BigInt(target.slot) << 112n),
			16,
		);
		return {
			...target,
			region: target.region ?? defaultRailwayRegion,
			realPrefix,
			virtualPrefix,
			dnsSuffix: `${target.name}.railway.internal`,
			nameserver: `${virtualPrefix.slice(0, -3)}10`,
		};
	});

	return {
		...args,
		virtualNetwork,
		registration: args.registration
			? { ...args.registration, virtualNetwork }
			: undefined,
		connectors: normalizedConnectors,
	};
}

function validateDynamicNetwork(value: string, exclusions: string[]): void {
	const length = Number(value.split("/")[1]);
	if (!Number.isInteger(length) || length < 10 || length > 16) {
		throw new Error(
			"registration.virtualNetwork must use a prefix from /10 through /16.",
		);
	}
	const base = parseIpv6Prefix(value, length, "registration.virtualNetwork");
	const ula = parseIpv6Prefix("fd00::/8", 8, "ULA network");
	if (base >> 120n !== ula >> 120n) {
		throw new Error("registration.virtualNetwork must be inside fd00::/8.");
	}
	for (const exclusion of exclusions) {
		const excludedLength = Number(exclusion.split("/")[1]);
		const excludedBase = parseIpv6Prefix(
			exclusion,
			excludedLength,
			"registration.excludedPrefixes",
		);
		const shorter = Math.min(length, excludedLength);
		const shift = 128n - BigInt(shorter);
		if (base >> shift === excludedBase >> shift) {
			throw new Error(
				`registration.virtualNetwork overlaps excluded prefix ${exclusion}.`,
			);
		}
	}
}

function validateTarget(target: TailbridgeConnectorTarget): void {
	validateName("connector name", target.name);
	if (!Number.isInteger(target.slot) || target.slot < 0 || target.slot > 31) {
		throw new Error(
			`connector ${target.name} slot must be an integer from 0 to 31.`,
		);
	}
	if (target.region !== undefined && !target.region.trim()) {
		throw new Error(`connector ${target.name} region must not be empty.`);
	}
}

function validateName(label: string, value: string): void {
	if (!namePattern.test(value)) {
		throw new Error(`${label} must match ${namePattern.source}.`);
	}
}

function validateCidr(label: string, value: string): void {
	const [address, prefix, extra] = value.split("/");
	const version = isIP(address);
	if (extra !== undefined || version === 0 || !/^\d+$/.test(prefix ?? "")) {
		throw new Error(`${label} must contain valid CIDRs.`);
	}
	const length = Number(prefix);
	if (length < 0 || length > (version === 4 ? 32 : 128)) {
		throw new Error(`${label} must contain valid CIDRs.`);
	}
}

function parseIpv6Prefix(value: string, length: number, label: string): bigint {
	const [address, prefix, extra] = value.split("/");
	if (extra !== undefined || prefix !== String(length) || isIP(address) !== 6) {
		throw new Error(`${label} must be an IPv6 /${length} prefix.`);
	}
	const groups = expandIpv6(address);
	let result = 0n;
	for (const group of groups) {
		result = (result << 16n) | BigInt(Number.parseInt(group, 16));
	}
	const hostBits = 128n - BigInt(length);
	const mask = ((1n << 128n) - 1n) ^ ((1n << hostBits) - 1n);
	if ((result & mask) !== result) {
		throw new Error(`${label} must use a canonical network address.`);
	}
	return result;
}

function expandIpv6(address: string): string[] {
	const [left = "", right = "", ...extra] = address.split("::");
	if (extra.length > 0) {
		throw new Error("The IPv6 address is invalid.");
	}
	const leftGroups = left ? left.split(":") : [];
	const rightGroups = right ? right.split(":") : [];
	const missing = 8 - leftGroups.length - rightGroups.length;
	return [
		...leftGroups,
		...Array.from({ length: missing }, () => "0"),
		...rightGroups,
	];
}

function formatIpv6Prefix(value: bigint, length: number): string {
	const groups = Array.from({ length: 8 }, (_, index) =>
		Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16),
	);
	let bestStart = -1;
	let bestLength = 0;
	for (let start = 0; start < groups.length; start += 1) {
		if (groups[start] !== "0") continue;
		let end = start;
		while (end < groups.length && groups[end] === "0") end += 1;
		if (end - start > bestLength) {
			bestStart = start;
			bestLength = end - start;
		}
		start = end - 1;
	}
	if (bestLength > 1) {
		groups.splice(bestStart, bestLength, "");
		if (bestStart === 0) groups.unshift("");
		if (bestStart + bestLength === 8) groups.push("");
	}
	return `${groups.join(":")}/${length}`;
}
