group "default" {
  targets = ["base-container", "nginx", "rust", "python", "base-container-builder", "nginx-builder", "rust-builder", "python-builder"]
}

target "common" {
  platforms = ["linux/amd64"]
}

target "base-container" {
  inherits = ["common"]
  context = "./base-container"
  tags = ["sovereign-stack/base-container:local"]
}

target "app" {
  inherits = ["common"]
  contexts = {
    "sovereign-stack/base-container:local" = "target:base-container"
  }
}

target "nginx" {
  inherits = ["app"]
  context = "./nginx"
  tags = ["sovereign-stack/nginx:local"]
}

target "rust" {
  inherits = ["app"]
  context = "./rust"
  tags = ["sovereign-stack/rust:local"]
}

target "python" {
  inherits = ["app"]
  context = "./python"
  tags = ["sovereign-stack/python:local"]
}

target "base-container-builder" {
  inherits = ["base-container"]
  target = "bootstrap-tools"
  tags = ["sovereign-stack/base-container-builder:local"]
}

target "nginx-builder" {
  inherits = ["nginx"]
  target = "static"
  tags = ["sovereign-stack/nginx-builder:local"]
}

target "rust-builder" {
  inherits = ["rust"]
  target = "build"
  tags = ["sovereign-stack/rust-builder:local"]
}

target "python-builder" {
  inherits = ["python"]
  target = "dependencies"
  tags = ["sovereign-stack/python-builder:local"]
}
