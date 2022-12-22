# datacare

[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)

Server which handels users, regions and stations. This service is the main point of operation.

## Building

```bash
    $ nix build
```

## Configuration

### Environment Variables

- **SALT_PATH** path to file containing the salt that is used for hashing the password
- **POSTGRES_HOST** host of postgres server
- **POSTGRES_PORT** port of postgres server
- **POSTGRES_PASSWORD_PATH** password under which the dvbdump database is protected

### Commandline Arguments

```
management server for dump-dvb

Usage: datacare [OPTIONS]

Options:
  -a, --api-host <API_HOST>  [default: 127.0.0.1]
  -p, --port <PORT>          [default: 8080]
  -s, --swagger
  -h, --help                 Print help information
  -V, --version              Print version information
```

## Documentation 

documentation can be found [here](https://docs.dvb.solutions/chapter_2_2_user_api.html).
