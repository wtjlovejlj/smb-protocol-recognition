FROM centos:7.9.2009
ENV MYPATH /root/project
WORKDIR  $MYPATH
RUN yum -y update \
&& yum -y install vim \
&& yum -y install git \
&& yum install -y gcc-c++ \
&& yum -y install wget \
&& wget -P /root/ https://studygolang.com/dl/golang/go1.17.11.linux-amd64.tar.gz \
&& tar -zxvf /root/go1.17.11.linux-amd64.tar.gz -C /usr/local \
&& echo export PATH=$PATH:/usr/local/go/bin >> /etc/profile \
&& source /etc/profile && go version \
&& echo "source /etc/profile" >> /root/.bashrc \
&& go env -w GOPROXY=https://goproxy.cn,direct \
&& go env -w GO111MODULE=on \