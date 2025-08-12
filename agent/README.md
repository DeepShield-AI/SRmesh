python3 build_yml.py
python3 containers_sh.py
python3 modify_conf.py
docker build -t frr-go -f Dockerfile.agent ..
docker build -t frr-go-controller -f Dockerfile.controller ..
docker compose up