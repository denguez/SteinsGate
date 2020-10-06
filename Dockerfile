FROM adoptopenjdk/openjdk11:alpine-jre
ADD build/libs/steinsgate-0.1.jar steinsgate.jar
ENTRYPOINT [ "sh", "-c", "java -jar steinsgate.jar --spring.config.location=classpath:/default.properties,$SPRING_CONFIG_LOCATION" ]