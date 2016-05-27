#!/bin/bash
# Define a timestamp function
timestamp() {
  date +"%Y-%m-%d:%T"
}
echo "$(timestamp): Cleaning UP of Docker containers BEGINS" >> /var/log/cleanup_docker.log 2>&1
echo "$(timestamp): Stopping all the running docker containers" >> /var/log/cleanup_docker.log 2>&1
docker ps -a | grep 'days ago' | awk '{print $1}' | xargs --no-run-if-empty docker stop  >> /var/log/cleanup_docker.log 2>&1
echo "$(timestamp): Removing all the docker containers" >> /var/log/cleanup_docker.log 2>&1
docker ps -a | grep 'days ago' | awk '{print $1}' | xargs --no-run-if-empty docker rm  >> /var/log/cleanup_docker.log 2>&1
echo "$(timestamp): Cleaning UP of Docker containers ENDS" >> /var/log/cleanup_docker.log 2>&1
