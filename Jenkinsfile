#!/usr/bin/env groovy
/* vim: set sw=4 expandtab: */
/*
 * About variables in Jenkins:
 *   - A variable declared with 'def' is local
 *   - A variable can only be assigned in Groovy (= inside "script" nodes)
 *   - In Groovy parts, variable can used directly (without $)
 *   - In strings within '', there is no way to use Jenkins variable (however,
 *     shell can interpret environement variables)
 *   - In strings within "", variables can be called with ${var}
 */

/* This Jenkinsfile has been tested with this Docker image:
 *     FROM alpine:3.12
 *     RUN apk add openjdk11-jre-headless openssh-server
 *     RUN apk add build-base openssh-client git cmake ninja pkgconfig linux-headers libnl3-dev
 */

pipeline {
    agent {
        label 'wisun_br_linux_node'
    }
    parameters {
        string(name: 'COMMIT_ID', defaultValue: 'refs/heads/master',
               description: 'Branch (with syntax <b>refs/heads/&lt;branchName&gt;</b>), tag (with syntax <b>refs/tags/&lt;tagName&gt;</b>) or commit-id to build. If blank, it will build the last pushed version (not necessary on master).')
    }
    stages {
        stage('Compile') {
            steps {
                dir('build-debug') {
                    sh "find . -mindepth 1 -delete"
                    sh "cmake -GNinja -DCMAKE_BUILD_TYPE=Debug .."
                    sh "ninja"
                }
            }
        }
    }
}

