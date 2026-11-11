# User service and terminal-session lifecycle

This project treats the management daemon as a user service, not as a child of
the TUI or of an interactive SSH shell.

## Supported lifecycle boundary

The packaged user unit starts:

```text
%h/.local/bin/karing-tui daemon run
```

under the systemd **user manager** and `default.target`. It is deliberately not
attached to a terminal, `graphical-session.target`, or a TUI process. Closing a
terminal, killing a management client, or exiting a future TUI must therefore
not be used as a signal to stop or restart the daemon/core.

`KillMode=control-group` applies in the opposite direction: when the user
service itself is intentionally stopped, systemd owns cleanup of the daemon
control group. This is service lifecycle, not TUI lifecycle.

## Logout and SSH disconnect are conditional

A user service can survive an SSH disconnect only while the user's systemd
manager remains alive. That condition is controlled by the host's login-manager
policy; it must not be inferred from the unit file alone.

For hosts where the daemon must continue after the user's last login session
ends, enable lingering for that user with the host administrator's normal
policy (for example, `loginctl enable-linger USER`). Verify the host's policy
rather than assuming linger is enabled.

Positive case:

- user manager remains active (including a correctly configured linger case);
- the service is enabled/started under that user manager;
- closing the TUI or SSH client does not stop the daemon.

Negative case:

- the host tears down the user manager at final logout and lingering is not
  enabled;
- the user service may stop with that manager;
- this is not a daemon crash and must not be documented as guaranteed
  background persistence.

Running `karing-tui daemon run` manually in an interactive shell is also not a
substitute for the packaged user service. The foreground command intentionally
honors SIGINT/SIGTERM from its own process environment.

## Regression evidence

The Linux lifecycle test launches the daemon independently, starts a separate
management-client process, kills that client with SIGKILL, and then verifies
that the same daemon PID/start timestamp is still serving the Unix socket.

A separate unit-file contract test rejects TTY/graphical-session coupling and
requires the packaged service to remain attached to `default.target` with
`Restart=on-failure` and `KillMode=control-group`.

Full T17 TUI-specific kill/terminal rendering coverage remains gated on the
actual TUI process being implemented; these tests establish the M1 service
boundary that the TUI must use.
