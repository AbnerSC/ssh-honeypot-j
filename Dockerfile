# syntax=docker/dockerfile:1
# =====================================================================
# ssh-honeypot-j 多架构镜像构建文件（linux/amd64 & linux/arm64）
#
# 多阶段构建：
#   - 编译阶段固定 --platform=$BUILDPLATFORM（构建机原生架构）运行 Maven，
#     fat-jar 为纯 Java 产物（sqlite-jdbc 运行时自动加载对应架构 native 库），
#     无需按目标架构重复编译，避免 QEMU 模拟，多架构构建速度更快
#   - 运行阶段基于 openjdk:25-ea-oracle（官方多架构镜像），与 pom.xml
#     中 fabric8 插件的镜像内容保持一致（app.jar + config.yaml）
#
# 本地手动构建多架构镜像：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ssh-honeypot-j:latest --push .
# 国内环境构建可注入阿里云 Maven 镜像加速依赖下载：
#   --build-arg MAVEN_MIRROR=https://maven.aliyun.com/repository/public
# =====================================================================

# ---------- 阶段一：Maven 编译打包 ----------
ARG MAVEN_IMAGE=maven:3-eclipse-temurin-25
# 运行时基础镜像：必须声明在第一个 FROM 之前（全局 ARG），否则后续 FROM 无法引用
ARG BASE_IMAGE=openjdk:25-ea-oracle
FROM --platform=$BUILDPLATFORM ${MAVEN_IMAGE} AS build
WORKDIR /build

# 可选：注入 Maven 镜像仓库（阿里云自动构建等国内环境可加速依赖下载）
ARG MAVEN_MIRROR=
RUN if [ -n "$MAVEN_MIRROR" ]; then \
        mkdir -p /root/.m2 && \
        printf '<settings><mirrors><mirror><id>mirror</id><mirrorOf>central</mirrorOf><url>%s</url></mirror></mirrors></settings>' \
            "$MAVEN_MIRROR" > /root/.m2/settings.xml; \
    fi

# 先拷贝 pom.xml 预取依赖，源码变更时可复用 Docker 层缓存
COPY pom.xml .
RUN mvn -B -q dependency:go-offline || true

COPY src ./src
RUN mvn -B -DskipTests clean package

# ---------- 阶段二：运行时镜像 ----------
FROM ${BASE_IMAGE}
WORKDIR /app

COPY --from=build /build/target/ssh-honeypot-j.jar app.jar
COPY config.yaml .

# JVM 参数与 pom.xml 中 MANIFEST JVM-Options 保持一致；
# MaxRAMPercentage：低配额容器下默认堆仅容器内存 1/4，显式放宽避免 OOM
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-XX:+UseCompactObjectHeaders", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]

EXPOSE 2222 2323 3306 5432 6379 8080
VOLUME ["/app/logs", "/app/db"]
