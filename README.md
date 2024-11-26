# Snowflake Development Container Tools

A container image with tools required to build with Snowflake and Streamlit. Refer to the [constraints](/constraints.txt)for packages added to this container image.

## Using 

A image using Python 3.11

```shell
docker pull ghcr.io/kameshsampath/snow-dev:py-311
```

The image also has `snow` cli installed, just run:

```
docker run -it -v "$HOME/.snowflake:/home/me/.snowflake" snow connection test -c trial
```

>[!IMPORTANT]
> When mounting volumes make sure the keys if any are accessible inside the container.