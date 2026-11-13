{
  description = "TycVirtualLab: private experiments, shareable tools";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/9bb52223f4f6a0cc606fd0852d8784f896c137d5";
  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
    in {
      packages = eachSystem (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.python3Packages.buildPythonApplication {
            pname = "tycvirtuallab";
            version = "0.1.0";
            src = self;
            pyproject = true;
            build-system = [ pkgs.python3Packages.setuptools ];
            nativeCheckInputs = [ pkgs.python3Packages.setuptools pkgs.nodejs ];
            checkPhase = ''
              runHook preCheck
              # Setuptools' disposable staging copy is not release source.
              # Keep the source-audit test strict instead of excluding build files.
              rm -rf build
              python -m unittest discover -s tests -v
              runHook postCheck
            '';
            pythonImportsCheck = [ "vfl" ];
            meta.mainProgram = "tycvl";
          };
        });
      checks = eachSystem (system: { package = self.packages.${system}.default; });
      devShells = eachSystem (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.mkShell { packages = [ pkgs.python3 pkgs.python3Packages.setuptools pkgs.gnumake pkgs.gcc ]; };
          emulation = pkgs.mkShell { packages = [ pkgs.python3 pkgs.gnumake pkgs.gcc pkgs.ghidra ]; };
        });
    };
}
