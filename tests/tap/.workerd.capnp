using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "main", worker = .tapWorker)],
);
const tapWorker :Workerd.Worker = (
  modules = [(name = "worker", esModule = embed ".build/run-workerd.js")],
  compatibilityDate = "2026-04-24",
  compatibilityFlags = ["nodejs_compat"]
);
