# T-0020 copy: the error-model keys that B13 does not define.
# Naming: keys are lowercase semantic words joined by hyphens (for example error-toast-retry), never sentences.
# The ux-docs check requires every key to be defined exactly once here, B13 or i18n/en/copy-deck.ftl, to match the
# exact text quoted in docs/UX/ERRORS.md, and to pass the Fluent style and claims rules.

error-validation-inline = Enter a valid value for this field.
error-summary-title = Check the highlighted fields.
error-toast-retry = The change was not saved. Try again.
error-banner-persistent = Part of this page is unavailable until the problem clears.
error-page-title = Something went wrong
error-page-body = The action did not complete. The reference below helps support find the cause.
error-request-id-label = Request ID: { $request_id }
error-ray-id-label = Ray ID: { $ray_id }
error-copy-ray-id = Copy Ray ID
error-copy-request-id = Copy request ID
error-retry-action = Try again
error-retry-after = Try again after { $seconds } seconds.
error-offline-banner = You are offline. Changes are sent when the connection returns.
error-reconnect-status = Connection lost. Retrying in { $seconds } seconds.
error-stale-partial = The values on screen may be out of date.
error-job-failed-inline = This job failed. The last result stays visible.
error-job-failed-notification = A background job failed. Open it to see the reference.
visitor-challenge-title = Checking your browser
visitor-challenge-progress = The check finishes automatically.
visitor-rate-limit-title = Too many requests
visitor-rate-limit-body = Too many requests reached this site from your network.
visitor-origin-error-title = This website is unavailable
visitor-origin-error-body = The site could not be reached. Try again in a moment.
visitor-unknown-host-title = Site not found
visitor-unknown-host-body = No website is configured at this address.
visitor-under-attack-title = A quick check is running
visitor-under-attack-body = The check finishes automatically and then the site opens.
visitor-suspended-title = Website unavailable
visitor-suspended-body = This website is paused. Contact the site owner if it continues.
