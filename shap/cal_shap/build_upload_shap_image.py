import subprocess
# Build command
registry_name = 'ttdungacr.azurecr.io'
tag = '15'

print(f"Building image: {registry_name}/cacidemo:{tag} from ./")
result_build = subprocess.run(
    f'docker build --platform linux/amd64 -t {registry_name}/cacidemo:{tag} ./', 
    capture_output=True, 
    text=True, 
    shell=True
)

if result_build.returncode != 0:
    print("--- Docker Build FAILED ---")
    print(result_build.stderr)
else:
    print("--- Docker Build SUCCESSFUL ---")
    print(result_build.stdout)
    # Push command - only run if the build succeeds
    print(f"\nPushing image: {registry_name}/cacidemo:{tag}")
    result_push = subprocess.run(
        f'docker push {registry_name}/cacidemo:{tag}', 
        capture_output=True, 
        text=True, 
        shell=True
    )

    if result_push.returncode != 0:
        print("--- Docker Push FAILED ---")
        print(result_push.stderr)
    else:
        print("--- Docker Push SUCCESSFUL ---")
        print(result_push.stdout)