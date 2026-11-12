int main(int argc, char **argv) {
  try {
    if (argc!=6) throw std::runtime_error("two libraries, selector, mode, corpus");
#ifdef __APPLE__
    if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0)) throw std::runtime_error("QoS");
#endif
    API first_api(argv[1]), second_api(argv[2]);
    if (first_api.cs_disasm_iter==second_api.cs_disasm_iter) throw std::runtime_error("libraries aliased");
    unsigned selector=std::stoul(argv[3]), mode=std::stoul(argv[4]);
    Session first(first_api,selector,mode), second(second_api,selector,mode);
    std::ifstream f(argv[5],std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),{});
    if(bytes.empty()) throw std::runtime_error("missing corpus");
    auto ref=run(first,bytes,1);
    if(!equal(ref,run(second,bytes,1))) throw std::runtime_error("unequal outputs");
    double start=process_cpu_ns(); run(first,bytes,1); double ticks=process_cpu_ns()-start;
    const unsigned reps=std::max(1u, unsigned(std::ceil(70000000.0/std::max(1.0,ticks))));
    auto expected=run(first,bytes,reps);
    if(!equal(expected,run(second,bytes,reps))) throw std::runtime_error("unequal repeated outputs");
    std::printf("{\"count\":%llu,\"repeats\":%u,\"ticks\":[",(unsigned long long)ref.instructions,reps);
    for(unsigned i=0;i<9;i++){
      if(i) std::printf(","); std::printf("[");
      // Store measurements in alternating first/second pairs and reverse
      // execution order twice per block to balance the running thread.
      double a[2],b[2];unsigned na=0,nb=0;
      for(unsigned j=0;j<4;j++){
        bool useFirst=((j==0||j==3)!=(i%2!=0));
        double time=process_cpu_ns();
        auto output=run(useFirst?first:second,bytes,reps);
        time=process_cpu_ns()-time;
        if(!equal(expected,output))throw std::runtime_error("result");
        if(useFirst)a[na++]=time;else b[nb++]=time;
      }
      if(i%2)std::printf("%.0f,%.0f,%.0f,%.0f]",b[0],a[0],b[1],a[1]);
      else std::printf("%.0f,%.0f,%.0f,%.0f]",a[0],b[0],a[1],b[1]);
    }
    std::printf("]}\n");return 0;
  } catch(const std::exception &err){std::fprintf(stderr,"%s\n",err.what());return 1;}
}
