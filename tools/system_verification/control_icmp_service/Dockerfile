FROM centos:centos8

WORKDIR /tmp
COPY ./run_traceroute_and_ping.sh .
RUN yum install -y traceroute

CMD ["bash", "./run_traceroute_and_ping.sh"]
