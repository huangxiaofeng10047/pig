FROM openjdk:17-ea-slim-buster

RUN mkdir -p /pig-gateway \
    && apt-get update \
&&  apt-get install fontconfig -y
WORKDIR /pig-gateway

ARG JAR_FILE=target/pig-gateway.jar

COPY ${JAR_FILE} app.jar

EXPOSE 9999

ENV TZ=Asia/Shanghai JAVA_OPTS="-Xms128m -Xmx256m -Djava.security.egd=file:/dev/./urandom"

CMD sleep 60; java $JAVA_OPTS -jar app.jar
