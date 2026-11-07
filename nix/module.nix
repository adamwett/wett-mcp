# NixOS module for wett-mcp: the connector server (services.wettMcp) and the
# per-host command endpoint (services.wettMcp.hostd). Publishing the server
# (cloudflared, DNS, Cloudflare Access) is left to the consuming config.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption mkEnableOption types;
  cfg = config.services.wettMcp;
  hcfg = cfg.hostd;
  system = pkgs.stdenv.hostPlatform.system;

  secretFile = types.nullOr (types.either types.path types.str);

  urlKey =
    { withKey }:
    types.nullOr (
      types.submodule {
        options = {
          url = mkOption {
            type = types.str;
            description = "Base URL of the service.";
          };
        }
        // lib.optionalAttrs withKey {
          keyFile = mkOption {
            type = types.either types.path types.str;
            description = "File holding the API key (read by systemd as a credential).";
          };
        };
      }
    );

  haRule = types.submodule {
    options = {
      service = mkOption {
        type = types.str;
        example = "light.*";
        description = "`domain.service` glob.";
      };
      entities = mkOption {
        type = types.listOf types.str;
        example = [ "light.*" ];
        description = "Entity id globs the service may target.";
      };
    };
  };

  hostdSettings = {
    units = hcfg.units;
    logDeny = hcfg.logDeny;
  }
  // lib.optionalAttrs (hcfg.ha != null) {
    ha = {
      inherit (hcfg.ha)
        url
        allow
        hideEntities
        exposeEntities
        ;
      tokenFile = toString hcfg.ha.tokenFile;
    };
  }
  // lib.optionalAttrs hcfg.agents.enable {
    agents = {
      inherit (hcfg.agents)
        workRoot
        stateDir
        cloneOwners
        maxConcurrent
        defaultMinutes
        maxMinutes
        maxPromptChars
        ompArgs
        ;
      omp = hcfg.agents.ompCommand;
      gh = hcfg.agents.ghCommand;
      envFiles = lib.mapAttrs (_: toString) hcfg.agents.envFiles;
    }
    // lib.optionalAttrs (hcfg.agents.systemNote != null) { inherit (hcfg.agents) systemNote; };
  };
  hostdConfigFile = pkgs.writeText "wett-mcp-hostd.json" (builtins.toJSON hostdSettings);

  # Secrets reach the service as systemd credentials; the JSON names them.
  credentials =
    lib.optional (cfg.sshKeyFile != null) "ssh-key:${toString cfg.sshKeyFile}"
    ++ lib.mapAttrsToList (name: h: "ssh-key-${name}:${toString h.keyFile}") (
      lib.filterAttrs (_: h: h.keyFile != null) cfg.hosts
    )
    ++ lib.optional (cfg.notify != null) "notify-token:${toString cfg.notify.tokenFile}"
    ++ lib.concatMap (
      name:
      let
        m = cfg.media.${name};
      in
      lib.optional (m != null && m ? keyFile) "${name}-key:${toString m.keyFile}"
    ) (lib.attrNames cfg.media);

  serverSettings = {
    inherit (cfg)
      publicUrl
      haHost
      agentsHost
      accessTokenTtl
      refreshTokenTtl
      sshKnownHostsFile
      authFailureAlert
      ;
    hosts = lib.mapAttrs (
      name: h: { inherit (h) ssh; } // lib.optionalAttrs (h.keyFile != null) { keyFile = "ssh-key-${name}"; }
    ) cfg.hosts;
    listen = { inherit (cfg.listen) host port; };
    stateDir = "/var/lib/wett-mcp";
    access = { inherit (cfg.access) teamDomain aud allowEmails; };
    cimd.allowedPrefixes = cfg.cimd.allowedPrefixes;
    dcr = { inherit (cfg.dcr) enable allowedRedirectUris; };
    sshKeyFile = if cfg.sshKeyFile != null then "ssh-key" else null;
    prometheus = cfg.prometheus;
    notify =
      if cfg.notify == null then
        null
      else
        {
          inherit (cfg.notify) url titlePrefix maxPerHour;
          tokenFile = "notify-token";
        };
    media = lib.mapAttrs (name: m: m // lib.optionalAttrs (m ? keyFile) { keyFile = "${name}-key"; }) (
      lib.filterAttrs (_: m: m != null) cfg.media
    );
    printer =
      if cfg.printer == null then
        null
      else
        {
          inherit (cfg.printer)
            uri
            maxBytes
            maxPages
            maxCopies
            ;
          jobUri =
            if cfg.printer.cupsQueue == null then null else "ipp://localhost:631/printers/${cfg.printer.cupsQueue}";
        };
    # Agents never run in-process: they belong to a host whose hostd runs as the agents' user.
    localHostd = removeAttrs hostdSettings [ "agents" ];
  };
  configFile = pkgs.writeText "wett-mcp.json" (builtins.toJSON serverSettings);

  ctl = pkgs.writeShellScriptBin "wett-mcp-ctl" ''
    # Run a wett-mcp admin command (revoke-all, mint-token) as the service's
    # dynamic user, so files in the state directory keep the right owner.
    exec ${config.systemd.package}/bin/systemd-run --quiet --pipe --wait --collect \
      --property=DynamicUser=yes --property=User=wett-mcp --property=StateDirectory=wett-mcp \
      ${cfg.package}/bin/wett-mcp --config ${configFile} "$@"
  '';
in
{
  options.services.wettMcp = {
    enable = mkEnableOption "the wett-mcp remote MCP server";

    package = mkOption {
      type = types.package;
      default = self.packages.${system}.wett-mcp;
      defaultText = lib.literalExpression "wett-mcp.packages.\${system}.wett-mcp";
      description = "The wett-mcp package.";
    };

    publicUrl = mkOption {
      type = types.str;
      example = "https://mcp.example.com";
      description = "Public origin of the server. The MCP endpoint is `<publicUrl>/mcp`.";
    };

    listen = {
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Listen address. Keep it on loopback behind the tunnel.";
      };
      port = mkOption {
        type = types.port;
        default = 8790;
        description = "Listen port.";
      };
    };

    access = {
      teamDomain = mkOption {
        type = types.str;
        example = "myteam.cloudflareaccess.com";
        description = "Cloudflare Access team domain; its certs verify the Access JWT on /oauth/authorize.";
      };
      aud = mkOption {
        type = types.str;
        description = "Application Audience (AUD) tag of the Access application covering /oauth/authorize.";
      };
      allowEmails = mkOption {
        type = types.listOf types.str;
        description = "Emails (from the Access JWT) allowed to approve grants.";
      };
    };

    cimd.allowedPrefixes = mkOption {
      type = types.listOf types.str;
      default = [ "https://claude.ai/" ];
      description = "URL prefixes a Client ID Metadata Document client_id must start with.";
    };

    dcr = {
      enable = mkEnableOption "Dynamic Client Registration (fallback for clients without CIMD)";
      allowedRedirectUris = mkOption {
        type = types.listOf types.str;
        default = [ "https://claude.ai/api/mcp/auth_callback" ];
        description = "The only redirect URIs a dynamically registered client may use.";
      };
    };

    accessTokenTtl = mkOption {
      type = types.ints.positive;
      default = 3600;
      description = "Access token lifetime, seconds.";
    };

    refreshTokenTtl = mkOption {
      type = types.ints.positive;
      default = 30 * 86400;
      description = "Refresh token lifetime, seconds. Refresh tokens rotate on every use.";
    };

    hosts = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.ssh = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "wett-mcp-hostd@otherhost";
            description = "SSH destination of the host's hostd; null means this machine (in-process).";
          };
          options.keyFile = mkOption {
            type = secretFile;
            default = null;
            description = "Private key for this host only (falls back to `sshKeyFile`).";
          };
        }
      );
      default = { };
      description = "Hosts the tools can query, by name.";
    };

    sshKeyFile = mkOption {
      type = secretFile;
      default = null;
      description = "Private key for reaching remote hostd endpoints.";
    };

    sshKnownHostsFile = mkOption {
      type = types.str;
      default = "/etc/ssh/ssh_known_hosts";
      description = "Known hosts for remote hostd endpoints (host keys are checked strictly).";
    };

    haHost = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Name (in `hosts`) of the host whose hostd holds the Home Assistant token.";
    };

    agentsHost = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Name (in `hosts`) of the host whose hostd has `agents` enabled. Turns on the agent_* tools;
        dispatch, send and stop need the `lab.agents` scope.
      '';
    };

    prometheus = mkOption {
      type = types.nullOr (
        types.submodule {
          options = {
            url = mkOption {
              type = types.str;
              example = "http://127.0.0.1:9090";
              description = "Prometheus base URL.";
            };
            hostLabel = mkOption {
              type = types.str;
              default = "instance";
              description = "Label naming the host in node_exporter series.";
            };
          };
        }
      );
      default = null;
      description = "Prometheus for prom_query and lab_overview.";
    };

    notify = mkOption {
      type = types.nullOr (
        types.submodule {
          options = {
            url = mkOption {
              type = types.str;
              description = "Endpoint taking POST {message, title} JSON with a bearer token.";
            };
            tokenFile = mkOption {
              type = types.either types.path types.str;
              description = "Bearer token file.";
            };
            titlePrefix = mkOption {
              type = types.str;
              default = "Claude";
              description = "Prefix for notification titles.";
            };
            maxPerHour = mkOption {
              type = types.ints.positive;
              default = 10;
              description = "Rate limit for lab_notify.";
            };
          };
        }
      );
      default = null;
      description = "Phone notifications (lab_notify, HA call mirroring, auth-failure alerts).";
    };

    media = {
      sonarr = mkOption {
        type = urlKey { withKey = true; };
        default = null;
        description = "Sonarr.";
      };
      radarr = mkOption {
        type = urlKey { withKey = true; };
        default = null;
        description = "Radarr.";
      };
      sabnzbd = mkOption {
        type = urlKey { withKey = true; };
        default = null;
        description = "SABnzbd.";
      };
      jellyfin = mkOption {
        type = urlKey { withKey = true; };
        default = null;
        description = "Jellyfin.";
      };
      qbittorrent = mkOption {
        type = urlKey { withKey = false; };
        default = null;
        description = "qBittorrent Web UI (must allow this host without login).";
      };
    };

    printer = mkOption {
      type = types.nullOr (
        types.submodule {
          options = {
            uri = mkOption {
              type = types.str;
              example = "ipp://Canon-printer.local:631/ipp/print";
              description = ''
                IPP URI (`ipp://` or `ipps://`) of the printer itself, for printer_status and, without
                `cupsQueue`, for jobs. Use a DHCP-reserved address, or an mDNS `.local` name (which needs
                `services.avahi.nssmdns4`).
              '';
            };
            cupsQueue = mkOption {
              type = types.nullOr (types.strMatching "[A-Za-z0-9_.-]+");
              default = null;
              example = "canon";
              description = ''
                Create a local CUPS driverless (IPP Everywhere) queue of this name for `uri` and send jobs
                through it. CUPS converts PDF, text and images for printers that only take raster, and holds
                jobs while the printer is busy or asleep. Enables `services.printing`.
              '';
            };
            maxBytes = mkOption {
              type = types.ints.positive;
              default = 10 * 1024 * 1024;
              description = "Largest document print_document accepts, bytes.";
            };
            maxPages = mkOption {
              type = types.ints.positive;
              default = 30;
              description = "Most pages one job may print, copies included.";
            };
            maxCopies = mkOption {
              type = types.ints.positive;
              default = 10;
              description = "Most copies per job.";
            };
          };
        }
      );
      default = null;
      description = "Network printer for printer_status (read) and print_document (`lab.write`).";
    };

    authFailureAlert = {
      threshold = mkOption {
        type = types.ints.positive;
        default = 20;
        description = "401 responses per window that trigger a notification.";
      };
      windowSeconds = mkOption {
        type = types.ints.positive;
        default = 300;
        description = "Alert window, seconds.";
      };
    };

    hostd = {
      enable = mkEnableOption "the SSH forced-command endpoint (wett-mcp-hostd) on this host";

      package = mkOption {
        type = types.package;
        default = self.packages.${system}.wett-mcp-hostd;
        defaultText = lib.literalExpression "wett-mcp.packages.\${system}.wett-mcp-hostd";
        description = "The hostd package.";
      };

      user = mkOption {
        type = types.str;
        default = "wett-mcp-hostd";
        description = "User the connector logs in as; its only command is hostd.";
      };

      createUser = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Create `user` as a dedicated system user. Set false to add the forced-command keys to an
          existing user instead, e.g. the agents' own user for `agents`.
        '';
      };

      authorizedKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Public keys allowed to run hostd (the server's sshKeyFile counterpart).";
      };

      units = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "nginx.service"
          "container@*.service"
        ];
        description = "Unit globs unit_status/unit_logs may touch on this host.";
      };

      logDeny = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra unit globs whose logs are never returned (on top of the built-in list).";
      };

      ha = mkOption {
        type = types.nullOr (
          types.submodule {
            options = {
              url = mkOption {
                type = types.str;
                example = "http://127.0.0.1:8123";
                description = "Home Assistant base URL.";
              };
              tokenFile = mkOption {
                type = types.either types.path types.str;
                description = "Long-lived token of a non-admin HA user, readable by the hostd user.";
              };
              allow = mkOption {
                type = types.listOf haRule;
                default = [
                  {
                    service = "light.*";
                    entities = [ "light.*" ];
                  }
                  {
                    service = "fan.*";
                    entities = [ "fan.*" ];
                  }
                  {
                    service = "scene.turn_on";
                    entities = [ "scene.*" ];
                  }
                ];
                description = ''
                  Service calls ha_call_service may make. The built-in deny list (locks, alarms,
                  covers, cameras, HA administration, command/notify services) always wins.
                '';
              };
              hideEntities = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = "Entity globs hidden from ha_states/ha_history.";
              };
              exposeEntities = mkOption {
                type = types.listOf types.str;
                default = [ ];
                description = "Entity globs shown even in hidden domains (person, device_tracker, ...).";
              };
            };
          }
        );
        default = null;
        description = "Home Assistant access through this host's hostd.";
      };

      agents = {
        enable = mkEnableOption ''
          the agent_* verbs: headless oh-my-pi (omp) coding agents run as `user` in transient
          `systemd-run --user` units. `user` needs a lingering systemd user manager, omp and gh on PATH,
          and is trusted with whatever credentials it holds
        '';
        workRoot = mkOption {
          type = types.str;
          default = "~/work";
          description = "Directory whose immediate subdirectories are the repos agents may work in.";
        };
        stateDir = mkOption {
          type = types.str;
          default = "~/.local/state/wett-agents";
          description = "Job state: meta, queued messages, per-turn results, raw events, omp sessions.";
        };
        cloneOwners = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "octocat" ];
          description = "GitHub owners whose repos agent_dispatch may clone (`owner/name`) into workRoot.";
        };
        maxConcurrent = mkOption {
          type = types.ints.positive;
          default = 3;
          description = "Running agent units allowed at once.";
        };
        defaultMinutes = mkOption {
          type = types.ints.positive;
          default = 60;
          description = "Run time budget when the dispatch names none.";
        };
        maxMinutes = mkOption {
          type = types.ints.positive;
          default = 240;
          description = "Cap on a run's time budget.";
        };
        maxPromptChars = mkOption {
          type = types.ints.positive;
          default = 20000;
          description = "Longest prompt or follow-up message accepted.";
        };
        ompCommand = mkOption {
          type = types.str;
          default = "omp";
          description = "omp executable (looked up on PATH unless absolute).";
        };
        ghCommand = mkOption {
          type = types.str;
          default = "gh";
          description = "gh executable, for cloning.";
        };
        ompArgs = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [
            "--approval-mode"
            "yolo"
          ];
          description = "Fixed extra omp arguments for every turn.";
        };
        envFiles = mkOption {
          type = types.attrsOf (types.either types.path types.str);
          default = { };
          example = {
            GH_TOKEN = "/run/secrets/github-token";
          };
          description = ''
            Environment variables read from files at each turn (and for cloning). The transient units
            don't inherit a login shell's environment.
          '';
        };
        systemNote = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Replaces the built-in note appended to every agent's system prompt.";
        };
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.haHost == null || cfg.hosts ? ${cfg.haHost};
          message = "services.wettMcp.haHost must name an entry of services.wettMcp.hosts.";
        }
        {
          assertion = cfg.agentsHost == null || cfg.hosts ? ${cfg.agentsHost};
          message = "services.wettMcp.agentsHost must name an entry of services.wettMcp.hosts.";
        }
        {
          assertion = lib.all (h: h.ssh == null || h.keyFile != null) (lib.attrValues cfg.hosts)
            || cfg.sshKeyFile != null;
          message = "services.wettMcp.sshKeyFile (or the host's keyFile) is required when a host is reached over SSH.";
        }
      ];

      environment.systemPackages = [ ctl ];

      systemd.services.wett-mcp = {
        description = "wett-mcp remote MCP server";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        path = [
          pkgs.openssh
          pkgs.coreutils
          config.systemd.package
        ];
        serviceConfig = {
          ExecStart = "${cfg.package}/bin/wett-mcp --config ${configFile} serve";
          DynamicUser = true;
          User = "wett-mcp";
          StateDirectory = "wett-mcp";
          StateDirectoryMode = "0700";
          # In-process hostd for this machine reads the journal.
          SupplementaryGroups = [ "systemd-journal" ];
          LoadCredential = credentials;
          Restart = "on-failure";
          RestartSec = 5;
          UMask = "0077";
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          CapabilityBoundingSet = "";
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_UNIX"
          ];
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
          ];
        };
      };
    })

    (lib.mkIf (cfg.enable && cfg.printer != null && cfg.printer.cupsQueue != null) {
      services.printing.enable = true;
      # Not hardware.printers.ensurePrinters: that runs lpadmin in cups.service's postStart, and
      # `lpadmin -m everywhere` fails while the printer is off, taking CUPS down with it. This unit retries.
      systemd.services.wett-mcp-cups-queue = {
        description = "CUPS driverless queue for the wett-mcp printer";
        wantedBy = [ "multi-user.target" ];
        requires = [ "cups.service" ];
        after = [
          "cups.service"
          "network-online.target"
        ];
        wants = [ "network-online.target" ];
        path = [ config.services.printing.package ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = 60;
        };
        script = ''
          lpadmin -p ${lib.escapeShellArg cfg.printer.cupsQueue} -v ${lib.escapeShellArg cfg.printer.uri} \
            -m everywhere -E
        '';
      };
    })

    (lib.mkIf hcfg.enable {
      users.users.${hcfg.user} = {
        openssh.authorizedKeys.keys = map (
          key: ''command="${hcfg.package}/bin/wett-mcp-hostd ${hostdConfigFile}",restrict ${key}''
        ) hcfg.authorizedKeys;
      }
      // lib.optionalAttrs hcfg.createUser {
        isSystemUser = true;
        group = hcfg.user;
        extraGroups = [ "systemd-journal" ];
        # sshd runs the forced command through the login shell.
        shell = pkgs.bash;
      };
      users.groups = lib.mkIf hcfg.createUser { ${hcfg.user} = { }; };
    })
  ];
}
