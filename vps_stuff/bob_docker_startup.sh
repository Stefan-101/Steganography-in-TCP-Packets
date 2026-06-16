docker build -t bob-img .
docker rm -f bob
docker run -d \
  --name bob \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_ADMIN \
  -v $(pwd)/src:/scripts \
  -v $(pwd)/http_server:/http_server \
  -p 80:80 \
  bob-img \
  bash -c "/scripts/bob.sh && sleep infinity"

docker logs -f bob