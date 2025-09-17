#!/bin/bash

USERNAME="dev"
DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"

# on macOS, the docker socket binded into the container belongs to root, which make problems when trying
# to interact with it. Therefore, we "forward" the host docker socket that was binded to /var/run/docker-host.sock
# to /var/run/docker.sock with socat.
# You can check that the docker socket si working with: curl --unix-socket /var/run/docker.sock http://localhost/version
if [ "${DOCKER_SOCKET_GID}" == '0' ]; then
  rm -rf /var/run/docker.sock
  ((socat UNIX-LISTEN:/var/run/docker.sock,fork,reuseaddr,mode=660,user=${USERNAME} UNIX-CONNECT:/var/run/docker-host.sock) 2>&1 >> /tmp/vscr-docker-from-docker.log) & > /dev/null
else
  if [ "$(cat /etc/group | grep :${DOCKER_SOCKET_GID}:)" = '' ]; then groupadd --gid ${DOCKER_SOCKET_GID} docker-host; fi
  if [ "$(id ${USERNAME} | grep -E "groups=.*(=|,)${DOCKER_SOCKET_GID}(")" = '' ]; then usermod -aG ${DOCKER_SOCKET_GID} ${USERNAME}; fi
fi

# if [ \"\$(cat /etc/group | grep :\${DOCKER_SOCKET_GID}:)\" = '' ]; then groupadd --gid \${DOCKER_SOCKET_GID} docker-host; fi \n\
# if [ \"\$(id ${USERNAME} | grep -E \"groups=.*(=|,)\${DOCKER_SOCKET_GID}\(\")\" = '' ]; then usermod -aG \${DOCKER_SOCKET_GID} ${USERNAME}; fi\n\

exec "$@"
