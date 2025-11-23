docker stop waterguru2mqtt
docker rm waterguru2mqtt
docker rmi -f waterguru2mqtt
./build.sh
./run.sh
docker image prune