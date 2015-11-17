#!/bin/bash
# Define a timestamp function
timestamp() {
  date +"%Y-%m-%d:%T"
}
echo "$(timestamp): Cleaning UP of Docker containers BEGINS" >> /var/log/cleanup_docker.log 2>&1
echo "$(timestamp): Stopping all the running docker containers" >> /var/log/cleanup_docker.log 2>&1
docker stop $(docker ps -a -q) >> /var/log/cleanup_docker.log 2>&1
echo "$(timestamp): Removing all the docker containers" >> /var/log/cleanup_docker.log 2>&1
docker rm $(docker ps -a -q) >> /var/log/cleanup_docker.log 2>&1
echo "$(timestamp): Cleaning UP of Docker containers ENDS" >> /var/log/cleanup_docker.log 2>&1
