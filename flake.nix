{
  description = "wett-mcp: remote MCP connector for a homelab (OAuth 2.1 + Cloudflare Access, allowlisted tools)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      py = pkgs.python3Packages;
    in
    {
      packages.${system} = {
        wett-mcp = py.buildPythonApplication {
          pname = "wett-mcp";
          version = "0.1.0";
          pyproject = true;
          src = ./.;
          build-system = [ py.setuptools ];
          dependencies = [
            py.mcp
            py.pyjwt
            py.cryptography
            py.httpx
            py.uvicorn
            py.starlette
          ];
          nativeCheckInputs = [
            py.pytestCheckHook
            py.pytest-asyncio
            pkgs.git # test_agents makes a repo to check clone-origin matching
          ];
          pythonImportsCheck = [ "wett_mcp.server" ];
          meta.mainProgram = "wett-mcp";
        };

        # Stdlib-only, so hosts that only run hostd don't pull in the server's closure.
        wett-mcp-hostd = pkgs.writers.writePython3Bin "wett-mcp-hostd" {
          flakeIgnore = [
            "E501"
            "W503"
          ];
        } (builtins.readFile ./src/wett_mcp/hostd.py);

        default = self.packages.${system}.wett-mcp;
      };

      nixosModules.default = import ./nix/module.nix self;

      checks.${system} =
        let
          eval = nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              self.nixosModules.default
              {
                system.stateVersion = "26.05";
                services.wettMcp = {
                  enable = true;
                  publicUrl = "https://mcp.example.test";
                  access = {
                    teamDomain = "team.example.test";
                    aud = "example-aud";
                    allowEmails = [ "owner@example.test" ];
                  };
                  hosts.local = { };
                  hosts.remote.ssh = "wett-mcp-hostd@remote.example.test";
                  hosts.box = {
                    ssh = "agent@box.example.test";
                    keyFile = "/run/secrets/example-box-key";
                  };
                  agentsHost = "box";
                  sshKeyFile = "/run/secrets/example-key";
                  haHost = "remote";
                  notify = {
                    url = "http://notify.example.test/notify";
                    tokenFile = "/run/secrets/example-notify";
                  };
                  printer = {
                    uri = "ipp://printer.example.test/ipp/print";
                    cupsQueue = "canon";
                  };
                  media.sonarr = {
                    url = "http://sonarr.example.test";
                    keyFile = "/run/secrets/example-sonarr";
                  };
                  hostd = {
                    enable = true;
                    authorizedKeys = [ "ssh-ed25519 AAAAexample" ];
                    units = [ "nginx.service" ];
                  };
                };
              }
            ];
          };
          svc = eval.config.systemd.services.wett-mcp.serviceConfig;
          # The agents side: hostd's keys on an existing user, agent verbs enabled.
          box = nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              self.nixosModules.default
              {
                system.stateVersion = "26.05";
                users.users.agent = {
                  isNormalUser = true;
                  openssh.authorizedKeys.keys = [ "ssh-ed25519 AAAAhuman" ];
                };
                services.wettMcp.hostd = {
                  enable = true;
                  user = "agent";
                  createUser = false;
                  authorizedKeys = [ "ssh-ed25519 AAAAconnector" ];
                  agents = {
                    enable = true;
                    cloneOwners = [ "octocat" ];
                    envFiles.GH_TOKEN = "/run/gh-token";
                  };
                };
              }
            ];
          };
          boxKeys = box.config.users.users.agent.openssh.authorizedKeys.keys;
        in
        {
          inherit (self.packages.${system}) wett-mcp wett-mcp-hostd;
          # The module evaluates and renders a config the server accepts.
          module = pkgs.runCommand "wett-mcp-module-check" { } ''
            exec_start=${pkgs.lib.escapeShellArg svc.ExecStart}
            config=$(echo "$exec_start" | sed -E 's/.*--config ([^ ]+) serve/\1/')
            ${pkgs.jq}/bin/jq -e '.localHostd.units == ["nginx.service"] and .notify.tokenFile == "notify-token"
              and .media.sonarr.keyFile == "sonarr-key" and .sshKeyFile == "ssh-key"
              and .agentsHost == "box" and .hosts.box.keyFile == "ssh-key-box" and .hosts.remote == {"ssh": "wett-mcp-hostd@remote.example.test"}
              and (.localHostd | has("agents") | not)
              and .printer == {"uri": "ipp://printer.example.test/ipp/print", "jobUri": "ipp://localhost:631/printers/canon",
                               "maxBytes": 10485760, "maxPages": 30, "maxCopies": 10}' "$config"
            test ${pkgs.lib.boolToString eval.config.services.printing.enable} = true
            echo ${pkgs.lib.escapeShellArg eval.config.systemd.services.wett-mcp-cups-queue.script} \
              | grep -q 'lpadmin -p canon -v ipp://printer.example.test/ipp/print'
            echo ${pkgs.lib.escapeShellArg (builtins.toJSON svc.LoadCredential)} | ${pkgs.jq}/bin/jq -e \
              'sort == ["notify-token:/run/secrets/example-notify", "sonarr-key:/run/secrets/example-sonarr", "ssh-key-box:/run/secrets/example-box-key", "ssh-key:/run/secrets/example-key"]'
            echo ${
              pkgs.lib.escapeShellArg (
                builtins.head eval.config.users.users.wett-mcp-hostd.openssh.authorizedKeys.keys
              )
            } | grep -q '^command="/nix/store/.*/bin/wett-mcp-hostd /nix/store/.*-wett-mcp-hostd.json",restrict ssh-ed25519 '
            test ${toString (builtins.length boxKeys)} = 2
            test ${pkgs.lib.boolToString box.config.users.users.agent.isNormalUser} = true
            test ${pkgs.lib.boolToString (box.config.users.groups ? wett-mcp-hostd)} = false
            key=${pkgs.lib.escapeShellArg (pkgs.lib.findFirst (k: pkgs.lib.hasInfix "AAAAconnector" k) "" boxKeys)}
            hostd_config=$(echo "$key" | sed -E 's/^command="[^ ]+ ([^"]+)",restrict .*/\1/')
            ${pkgs.jq}/bin/jq -e '.agents.cloneOwners == ["octocat"] and .agents.maxConcurrent == 3
              and .agents.maxMinutes == 240 and .agents.envFiles.GH_TOKEN == "/run/gh-token"
              and .agents.workRoot == "~/work" and .units == []' "$hostd_config"
            touch $out
          '';
        };

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          (pkgs.python3.withPackages (
            ps: with ps; [
              mcp
              pyjwt
              cryptography
              httpx
              uvicorn
              starlette
              pytest
              pytest-asyncio
            ]
          ))
        ];
      };
    };
}
