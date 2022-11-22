#!/bin/bash

set -eux
sam deploy --config-env "$APP_ENV"
