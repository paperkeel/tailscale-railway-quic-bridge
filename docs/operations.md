# Operations

## Upgrade the connector

Deploy an immutable connector image digest through Railway.

Wait for the new deployment to pass `/readyz`. Confirm that the edge reports the new software version.

The old connector drains for 15 seconds. Long TCP flows can close after the drain period.

Do not restart the old deployment during the overlap. If it reconnects, the edge rejects it while the newer connector is active.

## Upgrade the edge

Record the current image digest and Tailscale machine ID.

Pull the new immutable image. Restart the Compose service without deleting its volume.

Confirm the same machine ID after startup. Confirm the advertised route and direct path.

## Roll back

Set the prior immutable image digest. Restart only the affected component.

Do not replace the edge state volume.

## Rotate pair certificates

Generate a new pair with the setup CLI. Keep the connector identity unchanged.

Write the new pair to a new directory. The CLI refuses to replace an existing pair unless you pass `--force`.

Deploy matching certificates to both components during a maintenance window.

The current alpha requires a coordinated restart. Trust-bundle overlap will replace this process before version 1.0.

## Recover lost edge state

Start the edge with a new tagged, preauthorized credential. The edge registers as a new Tailscale machine.

The route auto-approver activates the advertised route. Remove the old offline machine after validation.
