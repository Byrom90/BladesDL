# BladesDL

A basic Dashlaunch substitute for Blades kernel (6770). Performs some of the basic tasks Dashlaunch would normally provide.

## Features

- Live is blocked via a DNS hook.
- System update strings are patched to $$ystemupdate.
- OG Xbox emulator is fixed by auto toggling the HV memory protections using syscall 0.
- System link ping limit removed.

## Credits

- c0z - Majority of the functions/hooks were backported from an old Dashlaunch source found online. If this is a problem please get in touch and I'll happily remove.
