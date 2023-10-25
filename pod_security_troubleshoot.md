kubectl get pod <pod-name> -n <namespace> -o=jsonpath='{.spec.containers[0].securityContext}'

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: your-pod-name
spec:
  securityContext:
    runAsUser: 999
  containers:
  - name: your-container-name
    image: your-image
    securityContext:
      runAsUser: 999
```

*999 = $(id -u username)

1. kubectl get serviceaccounts -n <namespace>
2. kubectl get roles -n <namespace>
3. kubectl get rolebindings -n <namespace>
```yaml
# Create a Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: <service-account-name>

# Create a Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: <role-name>
rules:
- apiGroups: [""]
  resources: ["pods", "pods/exec", "pods/log"]
  verbs: ["get", "list", "create", "update", "delete", "exec"]

# Create a RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: <role-binding-name>
subjects:
- kind: ServiceAccount
  name: <service-account-name>
  namespace: <namespace>
roleRef:
  kind: Role
  name: <role-name>
  apiGroup: rbac.authorization.k8s.io

# Deployment Manifest connected with SA
apiVersion: apps/v1
kind: Deployment
metadata:
  name: <deployment-name>
spec:
  template:
    spec:
      serviceAccountName: <service-account-name>
      containers:
      - name: <container-name>
        image: <container-image>

```
4. kubectl get psp
5. kubectl describe psp <psp-name>
6. Check Service Accounts:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: <service-account-name>
  annotations:
    kubernetes.io/psp: <psp-name>
```




