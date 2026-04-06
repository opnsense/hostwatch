1.0.13

- Optional periodic cleanups for ipv4/ipv6 addresses
- Allow build time overriding of default oui.csv path
- Optional sqlite bundling 
- Add cargo lockfile
- Format code (clippy)

1.0.12

- add update_interval which defaults to 90 seconds to prevent excessive database writes at the cost of an extra query

1.0.11

- replace auto_vacuum with vacuum on insert/update interval

1.0.9

- bugfix group option being ignored

