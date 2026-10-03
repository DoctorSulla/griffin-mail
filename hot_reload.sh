#!/bin/bash
app_name="griffin-mail"
pkill $app_name
cargo run &
