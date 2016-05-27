#!/bin/bash
# Define a timestamp function
timestamp() {
  date +"%Y-%m-%d:%T"
}
echo "$(timestamp): Cleaning UP of Docker containers BEGINS" >> cleanup_docker.log 2>&1
echo "$(timestamp): Stopping all the running docker containers" >> cleanup_docker.log 2>&1
docker ps -a | grep 'days ago' | awk '{print $1}' | xargs --no-run-if-empty docker stop  >> cleanup_docker.log 2>&1
echo "$(timestamp): Removing all the docker containers" >> cleanup_docker.log 2>&1
docker ps -a | grep 'days ago' | awk '{print $1}' | xargs --no-run-if-empty docker rm  >> cleanup_docker.log 2>&1
echo "$(timestamp): Cleaning UP of Docker containers ENDS" >> cleanup_docker.log 2>&1
