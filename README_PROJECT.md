\# Machine Learning-Based Kubernetes Security Assessment



\## Project Overview



This project implements a prototype system for assessing Kubernetes

security using machine learning together with Kubernetes security tools.



Two Kubernetes environments are used:



\- Secure cluster: `kind-ml-secure-cluster`

\- Insecure cluster: `kind-ml-insecure-cluster` based on Kubernetes Goat



\## Security Tools



\- Kubescape - Kubernetes configuration and compliance assessment

\- Trivy - Vulnerability assessment

\- Falco - Runtime monitoring



\## Machine Learning Pipeline



1\. Create secure and insecure Kubernetes environments.

2\. Extract Kubernetes configuration and runtime security features.

3\. Prepare and clean the dataset.

4\. Add controlled secure and insecure configurations.

5\. Perform duplicate-aware validation.

6\. Compare Logistic Regression, Decision Tree, and Random Forest.

7\. Select the final Logistic Regression model.

8\. Apply a decision threshold of 0.70.

9\. Generate workload-level security predictions.

10\. Calculate a model-derived 0-100 security score.



\## Final Model



Algorithm: Logistic Regression



Preprocessing: StandardScaler



Features: 16



Decision threshold: 0.70



Model file:



`ml\\final\_security\_model.joblib`



\## Final ML Validation



Duplicate-aware 5-fold evaluation:



\- Accuracy: 0.721

\- Precision: 0.540

\- Recall: 0.800

\- F1-score: 0.633



At threshold 0.70:



\- Accuracy: 0.771

\- Precision: 0.603

\- Recall: 0.800

\- F1-score: 0.681



Threshold 0.70 stability across five grouped seeds:



\- Accuracy: 0.771 - 0.796

\- Precision: 0.567 - 0.650

\- Recall: 0.800 - 0.800

\- F1-score: 0.663 - 0.705



\## Real Cluster Assessment



\### Secure Cluster



Workloads assessed: 9



Predicted SECURE: 9



Predicted INSECURE: 0



Model-derived security score: 74.17/100



Overall status: SECURE



\### Kubernetes Goat Cluster



Workloads assessed: 9



Predicted SECURE: 0



Predicted INSECURE: 9



Model-derived security score: 0.01/100



Overall status: INSECURE



\## Running the Final Demonstration



From the project root:



`scripts\\run\_final\_demo.cmd`



This assesses both the secure and insecure cluster datasets.



\## Important Results



\### Kubescape



Secure cluster:



\- Compliance: 79.91%

\- Coverage: 83.31%

\- Controls evaluated: 24/26

\- Resources passed: 22

\- Resources failed: 2



Kubernetes Goat:



\- Compliance: 50.17%

\- Coverage: 83.31%

\- Controls evaluated: 24/26

\- Resources passed: 23

\- Resources failed: 16



\### Trivy



Secure cluster:



`secure-app`



\- Critical: 2

\- High: 33

\- Medium: 48

\- Low: 26



Kubernetes Goat showed substantially larger vulnerability findings,

including:



`metadata-db`



\- Critical: 89

\- High: 1070

\- Medium: 1042

\- Low: 86



\### Falco



Falco 0.44.1 was successfully initialized in both clusters.



The syscall source was enabled using the modern BPF probe.



Observed runtime events included connections to the Kubernetes API server

from containers. Raw Falco event counts are not directly used as ML

features because legitimate Kubernetes system components can generate

similar events.



\## Project Limitations



\- The dataset contains only 46 samples.

\- Validation results are experimental and do not establish broad

&#x20; real-world generalization.

\- Duplicate-aware validation was used because repeated/controlled

&#x20; configurations are present.

\- The real secure and Kubernetes Goat samples are represented in the

&#x20; training dataset, so their results are not independent hold-out test

&#x20; accuracy.

\- The 0-100 security score is a model-derived prototype score and has

&#x20; not been independently calibrated.

\- Kubescape, Trivy, and Falco findings are supporting evidence and are

&#x20; not directly included in the current ML feature vector.



\## Important Files



\### Data



\- `data\\dataset\\cleaned\_dataset.csv`

\- `data\\dataset\\ml\_dataset\_v3.csv`

\- `data\\dataset\\variant\_plan.csv`



\### Final ML



\- `ml\\train\_final\_model.py`

\- `ml\\final\_security\_model.joblib`

\- `ml\\final\_assessment.py`



\### Evaluation



\- `ml\\compare\_models.py`

\- `ml\\evaluate\_16\_features.py`

\- `ml\\evaluate\_16\_thresholds.py`

\- `ml\\evaluate\_16\_threshold\_stability.py`

\- `ml\\feature\_importance.py`



\### Reports



\- `reports\\baseline\\`

\- `reports\\insecure\\`

\- `reports\\variants\\`

\- `reports\\ml\\`



\### Demo



\- `scripts\\run\_final\_demo.cmd`


## Unseen Cluster Validation

The final trained Logistic Regression model was tested on two newly created Kubernetes KIND clusters that were not used for model training. The model was not retrained using these clusters.

### Secure Test Cluster

- Cluster: `kind-testing-cluster-secure`
- Namespace: `secure-ns`
- Workload: `secure-app`
- ML prediction: **SECURE**
- Security probability: **0.7244107216**
- Security score: **72.44/100**
- Category: **MEDIUM**
- Kubescape NSA compliance: **79.86%**
- Kubescape: 19 passed, 2 failed, 5 action required
- Kubescape coverage: **24/26 controls (83%)**

### Insecure Test Cluster

- Cluster: `kind-testing-cluster-insecure`
- Namespace: `insecure-ns`
- Workload: `insecure-app`
- ML prediction: **INSECURE**
- Security probability: **0.0000000029**
- Security score: **0.00/100**
- Category: **LOW**
- Kubescape NSA compliance: **39.48%**
- Kubescape: 8 passed, 13 failed, 5 action required
- Kubescape coverage: **24/26 controls (83%)**

### Unseen-Cluster ML Metrics

- Samples: **2**
- Accuracy: **1.00**
- Precision: **1.00**
- Recall: **1.00**
- F1 Score: **1.00**

Confusion matrix:

```text
[[1 0]
 [0 1]]
Both unseen test workloads were classified correctly.

Important limitation: this evaluation contains only two intentionally constructed test workloads. Therefore, these 100% metrics describe this specific two-sample experiment and must not be interpreted as universal real-world accuracy or as proof of generalization to arbitrary Kubernetes clusters.

### Controlled Mixed-Configuration Test

A synthetic feature vector based on the secure workload was created by changing four security features:

- `allow_priv_esc_count`: 0 -> 1
- `readonly_rootfs_count`: 1 -> 0
- `service_account_token`: 0 -> 1
- `network_policy_present`: 1 -> 0

Original secure configuration:

- Probability: **0.7244107216**
- Status: **SECURE**
- Score: **72.44/100**

Mixed configuration:

- Probability: **0.0073877042**
- Status: **INSECURE**
- Score: **0.74/100**

This was a controlled feature-vector sensitivity experiment. It was not included in the two-sample unseen-cluster accuracy calculation.

### Validation Evidence

The complete evidence is stored under `reports\testing\`:

- `testing-secure-features.csv`
- `testing-insecure-features.csv`
- `testing-mixed-features.csv`
- `testing-secure-features_final_assessment.csv`
- `testing-insecure-features_final_assessment.csv`
- `testing-mixed-features_final_assessment.csv`
- `unseen_cluster_evaluation.csv`
- `unseen-cluster-final-evaluation.csv`
- `kubescape-testing-secure-nsa.json`
- `kubescape-testing-insecure-nsa.json`
- `UNSEEN_CLUSTER_VALIDATION.txt`
- `MIXED_CONFIGURATION_TEST.txt`

### Interpretation

The unseen-cluster experiment demonstrates that the already-trained model can process security features extracted from newly created Kubernetes clusters and produce workload-level security classifications.

The experiment also provides independent Kubescape evidence showing a higher NSA compliance result for the secure test namespace than for the insecure test namespace.

The ML security score and Kubescape compliance score are different measurements produced by different methods and should not be treated as equivalent numerical scales.
