FROM eclipse-temurin:21-jre
WORKDIR /app
# CI가 build/libs 에 boot jar 하나만 남겨 전달 (plain jar 는 제거됨)
COPY build/libs/*.jar app.jar
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
