#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "Usage: $0 DIRECT_BASE_URL RELAY_BASE_URL OUTPUT_DIRECTORY" >&2
	exit 2
fi

direct_url=${1%/}
relay_url=${2%/}
output_directory=$3
test_seconds=60

mkdir -p "$output_directory"

measure_latency() {
	local name=$1
	local base_url=$2
	local output_file="$output_directory/${name}-latency.csv"
	local deadline=$((SECONDS + test_seconds))
	local sequence=0

	printf 'sequence,http_code,connect_seconds,start_transfer_seconds,total_seconds\n' > "$output_file"
	while (( SECONDS < deadline )); do
		sequence=$((sequence + 1))
		curl --silent --show-error --output /dev/null \
			--connect-timeout 5 --max-time 10 \
			--write-out "$sequence,%{http_code},%{time_connect},%{time_starttransfer},%{time_total}\n" \
			"$base_url/ping" >> "$output_file"
		sleep 1
	done
}

measure_throughput() {
	local name=$1
	local base_url=$2
	local output_file="$output_directory/${name}-throughput.csv"

	printf 'http_code,download_bytes,elapsed_seconds,bytes_per_second\n' > "$output_file"
	set +e
	curl --silent --show-error --output /dev/null \
		--connect-timeout 5 --max-time "$test_seconds" \
		--write-out '%{http_code},%{size_download},%{time_total},%{speed_download}\n' \
		"$base_url/download" >> "$output_file"
	local curl_status=$?
	set -e
	if [[ $curl_status -ne 0 && $curl_status -ne 28 ]]; then
		return "$curl_status"
	fi
}

summarize() {
	local name=$1
	local latency_file="$output_directory/${name}-latency.csv"
	local throughput_file="$output_directory/${name}-throughput.csv"
	local summary_file="$output_directory/${name}-summary.txt"
	local samples
	local mean_ms
	local p50_ms
	local p95_ms
	local throughput_mbps

	samples=$(tail -n +2 "$latency_file" | wc -l)
	mean_ms=$(tail -n +2 "$latency_file" | awk -F, '{sum += $5 * 1000} END {printf "%.3f", sum / NR}')
	mapfile -t sorted < <(tail -n +2 "$latency_file" | awk -F, '{printf "%.6f\n", $5 * 1000}' | sort -n)
	p50_ms=${sorted[$(((samples - 1) * 50 / 100))]}
	p95_ms=${sorted[$(((samples - 1) * 95 / 100))]}
	throughput_mbps=$(tail -n 1 "$throughput_file" | awk -F, '{printf "%.3f", $4 * 8 / 1000000}')
	{
		printf 'path=%s\n' "$name"
		printf 'latency_samples=%s\n' "$samples"
		printf 'latency_mean_ms=%s\n' "$mean_ms"
		printf 'latency_p50_ms=%s\n' "$p50_ms"
		printf 'latency_p95_ms=%s\n' "$p95_ms"
		printf 'throughput_mbps=%s\n' "$throughput_mbps"
	} | tee "$summary_file"
}

measure_latency direct "$direct_url"
measure_throughput direct "$direct_url"
measure_latency relay "$relay_url"
measure_throughput relay "$relay_url"
summarize direct
summarize relay
