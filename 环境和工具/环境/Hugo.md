# 搭建



# docker

docker pull node 拉去node镜像



hugo 

wget下载https://github.com/gohugoio/hugo/releases/download/xxxxx.deb

dkpg -i xxxx.deb安装



wget 下载go

tar -xf go 解压

export PATH="$PATH:/etc/go/bin"  环境变量



hugo new site pickBottle 创建网站



cd pickBottle/themes 进入主题

git clone -b v0.7.2 https://github.com/google/docsy.git  拉去主题



进入主题安装依赖

```bash
cd docsy
git submodule update --init --recursive
npm install -D --save autoprefixer
npm install -D --save postcss-cli
```



启动

hugo server --bind "0.0.0.0" -p 880 --theme=docsy