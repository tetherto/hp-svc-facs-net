# hp-svc-facs-net

## Optional RPC server readiness

Pass `rpcServerReady` in the facility options to defer incoming connections until
the caller is ready to serve RPC. It is a function returning `true` or a promise
that resolves to `true`; any other result rejects the connection. Omitting the
hook preserves existing behavior.

The configured or explicitly supplied firewall runs first. Capability checks and
other `startRpcServer` options remain unchanged. The hook is checked for each new
connection; outgoing RPC and server construction are unaffected. Caller and
transport timeouts still apply.

The owner must settle pending readiness promises when startup fails or shutdown
begins, and return `false` for new connections during shutdown. The facility does
not infer readiness from worker events or drain already established connections.
