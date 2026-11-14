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
            version = "0.2.0";
            src = self;
            pyproject = true;
            build-system = [ pkgs.python3Packages.setuptools ];
            nativeCheckInputs = [ pkgs.python3Packages.setuptools pkgs.nodejs pkgs.gcc ];
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
      checks = eachSystem (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          package = self.packages.${system}.default;
          ghidra = pkgs.runCommand "tycvirtuallab-ghidra-check" {
            nativeBuildInputs = [ pkgs.python3 pkgs.ghidra ];
          } ''
            cp -R ${self} "$TMPDIR/source"
            chmod -R u+w "$TMPDIR/source"
            cd "$TMPDIR/source"
            export TYCVL_GHIDRA_INTEGRATION=1
            export GHIDRA_HEADLESS="${pkgs.ghidra}/bin/ghidra-analyzeHeadless"
            export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$TMPDIR/tycvl-settings -Dapplication.cachedir=$TMPDIR/tycvl-cache -Dapplication.tempdir=$TMPDIR/tycvl-temp"
            python -m unittest discover -s tests -p test_ghidra.py -v
            python -m unittest discover -s tests -p test_ghidra_windowed.py -v
            python -m unittest discover -s tests -p test_ghidra_reviewed.py -v
            touch "$out"
          '';
        });
      devShells = eachSystem (system:
        let pkgs = import nixpkgs { inherit system; }; in {
          default = pkgs.mkShell { packages = [ pkgs.python3 pkgs.python3Packages.setuptools pkgs.nodejs pkgs.gnumake pkgs.gcc ]; };
          emulation = pkgs.mkShell { packages = [ pkgs.python3 pkgs.gnumake pkgs.gcc pkgs.ghidra ]; };
          board = pkgs.mkShell {
            packages = [ pkgs.python3 ];
            LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.pixman pkgs.libgcrypt pkgs.SDL2 pkgs.zlib pkgs.libslirp pkgs.glib pkgs.libgpg-error ];
          };
        });
    };
}
