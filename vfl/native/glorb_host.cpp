#include "wled.h"
#include "sha256.h"
#include <cmath>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include TYCVL_EFFECT_SOURCE

static void ensure(bool condition,const char *message) {if(!condition)throw std::runtime_error(message);}
class FdBuffer : public std::streambuf {
  int descriptor;
  char storage[8192];
  int flush_buffer() {
    const auto size=pptr()-pbase();
    for(std::streamsize done=0;done<size;) {
      const auto written=::write(descriptor,pbase()+done,size_t(size-done));
      if(written<0&&errno==EINTR)continue;
      if(written<=0)return -1;
      done+=written;
    }
    setp(storage,storage+sizeof(storage));return 0;
  }
protected:
  int sync() override {return flush_buffer();}
  int_type overflow(int_type value) override {
    if(flush_buffer()<0)return traits_type::eof();
    if(!traits_type::eq_int_type(value,traits_type::eof())) {
      *pptr()=traits_type::to_char_type(value);pbump(1);
    }
    return traits_type::not_eof(value);
  }
public:
  explicit FdBuffer(int fd):descriptor(fd) {setp(storage,storage+sizeof(storage));}
  int close() {
    const auto flushed=flush_buffer();
    const auto result=::close(descriptor);descriptor=-1;
    return flushed<0 ? -1 : result;
  }
  ~FdBuffer() override {if(descriptor>=0) {flush_buffer();::close(descriptor);}}
};
static uint64_t number(std::istream &in,uint64_t maximum) {
  std::string s;ensure(bool(in>>s),"missing number");
  ensure(!s.empty()&&s.find_first_not_of("0123456789")==std::string::npos,"invalid unsigned integer");
  const auto value=std::stoull(s);ensure(value<=maximum,"number exceeds limit");return value;
}
static std::string pixel_hex(const std::vector<uint32_t> &pixels) {
  std::ostringstream out;out<<std::hex<<std::setfill('0');
  for(auto color:pixels)out<<std::setw(2)<<unsigned(R(color))<<std::setw(2)<<unsigned(G(color))<<std::setw(2)<<unsigned(B(color));
  return out.str();
}
static std::string state_hex() {
  std::ostringstream out;out<<std::hex<<std::setfill('0');
  const uint32_t values[]={SEGMENT.step,SEGMENT.call,uint32_t(SEGMENT.aux0)|(uint32_t(SEGMENT.aux1)<<16)};
  for(auto value:values)for(unsigned b=0;b<4;++b)out<<std::setw(2)<<unsigned(uint8_t(value>>(b*8)));
  return out.str();
}
int main(int argc,char **argv) {
  try {
    if(argc==2&&std::string(argv[1])=="--abi") {
      const uint16_t marker=1;
      std::cout<<"{\"schema\":\"tycvl.native-abi.v1\",\"pointer_bits\":"<<sizeof(void*)*CHAR_BIT
               <<",\"long_bits\":"<<sizeof(long)*CHAR_BIT<<",\"size_t_bits\":"<<sizeof(size_t)*CHAR_BIT
               <<",\"int_bits\":"<<sizeof(int)*CHAR_BIT<<",\"char_bits\":"<<CHAR_BIT
               <<",\"float_bits\":"<<sizeof(float)*CHAR_BIT<<",\"double_bits\":"<<sizeof(double)*CHAR_BIT
               <<",\"float_ieee754\":"<<(std::numeric_limits<float>::is_iec559?"true":"false")
               <<",\"char_signed\":"<<(std::numeric_limits<char>::is_signed?"true":"false")
               <<",\"endianness\":\""<<(*reinterpret_cast<const uint8_t*>(&marker)?"little":"big")
               <<"\",\"math_runtime\":\"host-standard-library\""
#if defined(__GLIBC__)
               <<",\"libc\":\"glibc\",\"libc_major\":"<<__GLIBC__<<",\"libc_minor\":"<<__GLIBC_MINOR__
#else
               <<",\"libc\":\"unidentified\""
#endif
               <<"}\n";
      return 0;
    }
    ensure(argc==3,"usage: TycGlorbHost COMMANDS OUTPUT");
    std::ifstream source(argv[1],std::ios::binary);ensure(bool(source),"cannot open commands");
    std::string raw((std::istreambuf_iterator<char>(source)),{});
    ensure(raw.size()<=8*1024*1024,"command file too large");
    std::istringstream commands(raw);std::string line,nonce;
    ensure(bool(std::getline(commands,line)),"missing header");
    std::istringstream header(line);std::string magic,extra;header>>magic>>nonce;
    ensure(magic=="TycGlorb1"&&nonce.size()==32&&nonce.find_first_not_of("0123456789abcdef")==std::string::npos&&!(header>>extra),"invalid header");
    const int fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    ensure(fd>=0,"output exists or cannot be created");
    FdBuffer buffer(fd);std::ostream output(&buffer);
    output<<"B "<<nonce<<' '<<tyc_sha256(raw)<<'\n';
    glorb_fx.setup();
    const std::string expected[]={"Colorwaves@","Running@","Frizzles@","Black Hole@","Hiphotic@","Tartan@"};
    ensure(strip.effects.size()==6,"unsupported renderer registration count");
    for(unsigned i=0;i<6;++i)ensure(strip.names[i].rfind(expected[i],0)==0,"unsupported renderer registration order");
    unsigned effect=0,frames=0;uint64_t previous=0;bool layout=false,settings=false,palette=false;
    while(std::getline(commands,line)) {
      ensure(!line.empty(),"empty command");std::istringstream row(line);std::string op;row>>op;
      if(op=="layout") {
        ensure(!layout&&!frames,"duplicate layout");
        tyc_width=number(row,256);tyc_height=number(row,256);tyc_physical=number(row,65536);
        ensure(tyc_width&&tyc_height&&tyc_physical&&tyc_width*tyc_height<=65536,"invalid layout");
        tyc_map.resize(tyc_width*tyc_height);tyc_pixels.assign(tyc_map.size(),0);
        std::set<int> seen;
        for(auto &entry:tyc_map) {std::string token;ensure(bool(row>>token),"missing map entry");
          if(token=="-1")entry=-1;else {std::istringstream item(token);entry=number(item,tyc_physical-1);ensure(seen.insert(entry).second,"duplicate mapped pixel");}}
        Segment::maxWidth=tyc_width;layout=true;
      } else if(op=="palette") {
        for(auto &color:tyc_palette) {const auto r=number(row,255),g=number(row,255),b=number(row,255);color=RGBW32(r,g,b,0);}
        palette=true;
      } else if(op=="settings") {
        const unsigned next=number(row,5);
        if(!settings||next!=effect) {SEGMENT.step=SEGMENT.call=0;SEGMENT.aux0=SEGMENT.aux1=0;std::fill(tyc_pixels.begin(),tyc_pixels.end(),0);}
        effect=next;SEGMENT.speed=number(row,255);SEGMENT.intensity=number(row,255);
        SEGMENT.custom1=number(row,255);SEGMENT.custom2=number(row,255);SEGMENT.custom3=number(row,31);
        SEGMENT.check1=number(row,1);paletteBlend=number(row,3);SEGMENT.palette=number(row,255);
        ensure(SEGMENT.palette!=0,"palette zero requires an explicit color-gamma/video-scale model");
        for(auto &color:SEGMENT.colors)color=number(row,0xffffffffU);
        settings=true;
      } else if(op=="frame") {
        ensure(layout&&settings&&palette,"frame before configuration");
        const auto index=number(row,1000000),timestamp=number(row,std::numeric_limits<uint64_t>::max());
        ensure(index==frames&&(!frames||timestamp>previous),"nonmonotonic frame");
        double volume;ensure(bool(row>>volume)&&std::isfinite(volume)&&volume>=0&&volume<=65535,"invalid volume");
        tyc_volume=float(volume);tyc_audio_reads=0;strip.now=uint32_t(timestamp/1000);
        strip.effects.at(effect)();++SEGMENT.call;
        std::vector<uint32_t> physical(tyc_physical,0);
        for(size_t i=0;i<tyc_map.size();++i)if(tyc_map[i]>=0)physical[tyc_map[i]]=tyc_pixels[i];
        uint32_t volume_bits;std::memcpy(&volume_bits,&tyc_volume,4);
        output<<"F "<<frames<<' '<<timestamp<<' '<<volume_bits<<' '<<tyc_audio_reads<<' '
              <<pixel_hex(tyc_pixels)<<' '<<pixel_hex(physical)<<' '<<state_hex()<<'\n';
        ++frames;previous=timestamp;
      } else throw std::runtime_error("unknown command");
      ensure(!(row>>extra),"extra command arguments");
    }
    ensure(frames>0,"no frames");output<<"E "<<frames<<'\n';output.flush();
    ensure(bool(output),"output write failed");ensure(buffer.close()==0,"output close failed");
    return 0;
  } catch(const std::exception &error) {std::cerr<<"TycGlorbHost: "<<error.what()<<'\n';return 2;}
}
