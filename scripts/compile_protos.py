import os
import subprocess
import sys

def compile_protos():
    """Compile les fichiers .proto en fichiers Python."""
    proto_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../protos'))
    output_dir = proto_dir  # On génère les fichiers dans le même dossier

    # Vérifier que le dossier protos existe
    if not os.path.exists(proto_dir):
        print(f"Le dossier {proto_dir} n'existe pas.")
        sys.exit(1)

    # Compiler chaque fichier .proto
    for proto_file in os.listdir(proto_dir):
        if proto_file.endswith('.proto'):
            proto_path = os.path.join(proto_dir, proto_file)
            print(f"Compilation de {proto_file}...")
            
            try:
                subprocess.run([
                    'python', '-m', 'grpc_tools.protoc',
                    f'--proto_path={proto_dir}',
                    f'--python_out={output_dir}',
                    f'--grpc_python_out={output_dir}',
                    proto_path
                ], check=True)
                print(f"✓ {proto_file} compilé avec succès.")
            except subprocess.CalledProcessError as e:
                print(f"✗ Erreur lors de la compilation de {proto_file}: {e}")
                sys.exit(1)
            except FileNotFoundError:
                print("✗ grpc_tools.protoc non trouvé. Assurez-vous d'avoir installé grpcio-tools.")
                print("  Vous pouvez l'installer avec: pip install grpcio-tools")
                sys.exit(1)

if __name__ == '__main__':
    compile_protos() 