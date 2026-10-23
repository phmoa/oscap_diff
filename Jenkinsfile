// Copyright (c) DED BUILD DEVOPS. All rights reserved.
//
// Jenkins pipeline for oscap_diff.py: runs the tests, compares the VMAAS and
// TOOLKIT OpenSCAP scan zips and keeps the report with the build.
//
// Build result:
//   SUCCESS   no regressed or new failing rules
//   UNSTABLE  rules regressed or new rules fail (only with FAIL_ON_REGRESSION)
//   FAILURE   tests failed, missing parameters/scan zips, or any other error
//
// Plugins: Pipeline (declarative). Optional: HTML Publisher, to show the report
// on the build page. Without it the report is still in the build artifacts.

pipeline {
    // The agent needs python3 (3.8 or newer). No other dependency.
    // With the Docker Pipeline plugin you can use instead:
    //   agent { docker { image 'python:3.12-slim' } }
    agent any

    parameters {
        string(name: 'VMAAS_SCAN', defaultValue: 'scans/vmaas.zip',
               description: 'Path, in the workspace, of the zip with the VMAAS scan results')
        string(name: 'TOOLKIT_SCAN', defaultValue: 'scans/toolkit.zip',
               description: 'Path, in the workspace, of the zip with the TOOLKIT scan results')
        string(name: 'VMAAS_VERSION', defaultValue: '', description: 'VMAAS version (required)')
        string(name: 'TOOLKIT_VERSION', defaultValue: '', description: 'TOOLKIT version (required)')
        string(name: 'APP_NAME', defaultValue: '', description: 'Application name (required)')
        booleanParam(name: 'FAIL_ON_REGRESSION', defaultValue: true,
                     description: 'Mark the build UNSTABLE when a rule regressed or a new rule fails')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '50'))
        timeout(time: 30, unit: 'MINUTES')
    }

    environment {
        DIFF_ZIP        = "oscap-diff-${env.BUILD_NUMBER}.zip"
        // Expose the parameters to the shell steps explicitly, so they are set on
        // every build, including the first one (before Jenkins knows the parameters).
        VMAAS_SCAN      = "${params.VMAAS_SCAN ?: ''}"
        TOOLKIT_SCAN    = "${params.TOOLKIT_SCAN ?: ''}"
        VMAAS_VERSION   = "${params.VMAAS_VERSION ?: ''}"
        TOOLKIT_VERSION = "${params.TOOLKIT_VERSION ?: ''}"
        APP_NAME        = "${params.APP_NAME ?: ''}"
    }

    stages {
        stage('Test') {
            steps {
                sh 'python3 --version && python3 -m unittest -v test_oscap_diff'
            }
        }

        stage('Get scans') {
            steps {
                // Put the two scan zips at VMAAS_SCAN and TOOLKIT_SCAN here, for example
                // from the scan jobs with the Copy Artifact plugin:
                //   copyArtifacts(projectName: 'vmaas-scan', selector: lastSuccessful(),
                //                 filter: '**/*.zip', target: 'scans', flatten: true)
                sh '''
                    for f in "$VMAAS_SCAN" "$TOOLKIT_SCAN"; do
                        if [ ! -f "$f" ]; then
                            echo "Scan zip not found: $f" >&2
                            exit 1
                        fi
                    done
                    ls -l "$VMAAS_SCAN" "$TOOLKIT_SCAN"
                '''
            }
        }

        stage('Report') {
            steps {
                // Remove the previous build's output so a failed run can't leave an old report behind.
                sh 'rm -rf oscap-diff oscap-diff-*.zip'
                script {
                    env.FAIL_FLAG = params.FAIL_ON_REGRESSION ? '--fail-on-regression' : ''
                    // Parameters are passed through environment variables, never pasted
                    // into the shell command, so their content can't change the command.
                    int rc = sh(returnStatus: true, script: '''
                        python3 oscap_diff.py \
                            --vmaas-scan "$VMAAS_SCAN" \
                            --toolkit-scan "$TOOLKIT_SCAN" \
                            --vmaas-version "$VMAAS_VERSION" \
                            --toolkit-version "$TOOLKIT_VERSION" \
                            --app-name "$APP_NAME" \
                            --outdir oscap-diff \
                            --zip "$DIFF_ZIP" \
                            $FAIL_FLAG
                    ''')
                    if (rc == 2) {
                        unstable('Regressed or new failing rules found: see the OpenSCAP diff report')
                    } else if (rc != 0) {
                        error("oscap_diff.py failed with exit code ${rc} (see the log above)")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'oscap-diff-*.zip, oscap-diff/report.html, oscap-diff/diff.json',
                             allowEmptyArchive: true
            script {
                if (fileExists('oscap-diff/report.html')) {
                    try {
                        publishHTML(target: [
                            reportName           : 'OpenSCAP diff',
                            reportDir            : 'oscap-diff',
                            reportFiles          : 'report.html',
                            keepAll              : true,
                            alwaysLinkToLastBuild: true,
                            allowMissing         : false
                        ])
                    } catch (NoSuchMethodError e) {
                        echo 'HTML Publisher plugin not installed: the report is in the build artifacts.'
                    }
                }
            }
        }
    }
}
