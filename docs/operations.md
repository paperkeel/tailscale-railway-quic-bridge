# Operations

## Upgrade the Tailbridge connector

1. Deploy an immutable Tailbridge connector image digest through Railway.

2. Wait for the new deployment to pass `/readyz`.

3. Confirm that the Tailbridge edge reports the new software version.

   The old Tailbridge connector drains for 15 seconds. Long TCP flows can close after the drain period.

4. Do not restart the old deployment during the overlap.

   The Tailbridge edge rejects the old deployment if it reconnects while the new deployment is active.

## Upgrade the Tailbridge edge

1. Record the current image digest.

2. Record the Tailscale machine ID.

3. Pull the new immutable Tailbridge edge image.

4. Restart the Compose service without deleting its volume.

5. Confirm that the Tailscale machine ID did not change.

6. Confirm that the Tailscale machine advertises the expected route.

7. Confirm that `tailscale ping` reports a direct path.

## Roll back

1. Set the prior immutable image digest.

2. Restart only the Tailbridge component that you rolled back.

3. Do not replace the Tailbridge edge state volume.

## Rotate Tailbridge certificates

1. Generate new certificates with the Tailbridge CLI.

2. Keep the connector identity unchanged.

3. Write the new certificates to a new directory.

   The Tailbridge CLI refuses to replace existing files unless you pass `--force`.

4. Deploy matching certificates to both Tailbridge components during a maintenance window.

5. Restart both Tailbridge components at the same time.

   The current alpha does not support trust-bundle overlap.

## Recover lost edge state

1. Start the Tailbridge edge with a new tagged, preauthorized credential.

   The Tailbridge edge registers as a new Tailscale machine.

2. Confirm that the route auto-approver activates the advertised route.

3. Validate the new Tailscale machine.

4. Remove the old offline Tailscale machine.
