docker build -t alice-img .
docker rm -f alice
docker run -it \
  --name alice \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_ADMIN \
  -v $(pwd)/src:/scripts \
  alice-img \
  bash -c "/scripts/alice.sh && /bin/bash"
