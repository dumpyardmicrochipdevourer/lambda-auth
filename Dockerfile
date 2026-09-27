FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
ENV MAVEN_OPTS="-Xmx384m"
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src src
RUN mvn -q -B -DskipTests package && cp target/*.jar /app.jar

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app app
COPY --from=build /app.jar /app/app.jar
USER app
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+UseSerialGC -XX:TieredStopAtLevel=1"
EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s \
  CMD wget -qO- http://127.0.0.1:8081/actuator/health || exit 1
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
