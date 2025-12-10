sudo python use_model.py \
  --live \
  --iface en0 \
  --duration 60 \
  --capture-method scapy \
  --model src/model/svm_pipeline.joblib \
  --outdir outputs