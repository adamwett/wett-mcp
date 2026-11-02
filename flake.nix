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
                  sshKeyFile = "/run/secrets/example-key";
                  haHost = "remote";
                  notify = {
                    url = "http://notify.example.test/notify";
                    tokenFile = "/run/secrets/example-notify";
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
        in
        {
          inherit (self.packages.${system}) wett-mcp wett-mcp-hostd;
          # The module evaluates and renders a config the server accepts.
          module = pkgs.runCommand "wett-mcp-module-check" { } ''
            exec_start=${pkgs.lib.escapeShellArg svc.ExecStart}
            config=$(echo "$exec_start" | sed -E 's/.*--config ([^ ]+) serve/\1/')
            ${pkgs.jq}/bin/jq -e '.localHostd.units == ["nginx.service"] and .notify.tokenFile == "notify-token"
              and .media.sonarr.keyFile == "sonarr-key" and .sshKeyFile == "ssh-key"' "$config"
            echo ${pkgs.lib.escapeShellArg (builtins.toJSON svc.LoadCredential)} | ${pkgs.jq}/bin/jq -e \
              'sort == ["notify-token:/run/secrets/example-notify", "sonarr-key:/run/secrets/example-sonarr", "ssh-key:/run/secrets/example-key"]'
            echo ${
              pkgs.lib.escapeShellArg (
                builtins.head eval.config.users.users.wett-mcp-hostd.openssh.authorizedKeys.keys
              )
            } | grep -q '^command="/nix/store/.*/bin/wett-mcp-hostd /nix/store/.*-wett-mcp-hostd.json",restrict ssh-ed25519 '
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
