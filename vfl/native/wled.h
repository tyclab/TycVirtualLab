#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#define PROGMEM
#define REGISTER_USERMOD(value)
#define USERMOD_ID_AUDIOREACTIVE 32
#define USERMOD_ID_USER_FX 1
#define BLACK 0U
#define R(c) uint8_t(uint32_t(c)>>16)
#define G(c) uint8_t(uint32_t(c)>>8)
#define B(c) uint8_t(uint32_t(c))
#define W(c) uint8_t(uint32_t(c)>>24)
#define RGBW32(r,g,b,w) ((uint32_t(w)<<24)|(uint32_t(r)<<16)|(uint32_t(g)<<8)|uint32_t(b))

using TycPalette = std::array<uint32_t,16>;
inline TycPalette tyc_palette{};
inline std::vector<int> tyc_map;
inline std::vector<uint32_t> tyc_pixels;
inline unsigned tyc_width=20,tyc_height=6,tyc_physical=83;
inline uint8_t paletteBlend=0;
inline float tyc_volume=0;
inline unsigned tyc_audio_reads=0;
enum TBlendType { NOBLEND, LINEARBLEND };

inline uint8_t tyc_scale8(uint8_t value,uint8_t factor) {
  return uint16_t(value)*(uint16_t(factor)+1)>>8;
}

inline uint32_t color_add(uint32_t a,uint32_t b,bool fast=false) {
  unsigned c[4]={unsigned(R(a))+R(b),unsigned(G(a))+G(b),unsigned(B(a))+B(b),unsigned(W(a))+W(b)};
  const unsigned top=*std::max_element(c,c+4);
  // WLED 0.14: false rescales all channels together; true clips each channel.
  for (auto &v:c) v=!fast&&top>255 ? v*255/top : std::min(v,255U);
  return RGBW32(c[0],c[1],c[2],c[3]);
}

inline uint32_t ColorFromPalette(const TycPalette &pal,uint8_t index,uint8_t brightness,TBlendType blend) {
  const uint32_t a=pal[index>>4],b=pal[((index>>4)+1)&15];
  const unsigned fraction=(index&15)<<4;
  uint8_t channels[3]={R(a),G(a),B(a)};
  const uint8_t next[3]={R(b),G(b),B(b)};
  for (unsigned c=0;c<3;++c) {
    if (fraction && blend!=NOBLEND)
      channels[c]=uint8_t(tyc_scale8(channels[c],255-fraction)+tyc_scale8(next[c],fraction));
    if (brightness!=255)
      channels[c]=brightness ? tyc_scale8(channels[c],uint8_t(brightness+1)) : 0;
  }
  return RGBW32(channels[0],channels[1],channels[2],0);
}

struct Segment {
  static inline unsigned maxWidth=20;
  unsigned start=0,startY=0;
  uint8_t speed=128,intensity=128,custom1=128,custom2=128,custom3=16,palette=1,soundSim=0;
  bool check1=false;
  uint32_t step=0,call=0;
  uint16_t aux0=0,aux1=0;
  std::array<uint32_t,3> colors{};
  bool is2D() const {return tyc_height>1;}
  uint32_t getPixelColorXY(int x,int y) const {
    if (x<0||y<0||unsigned(x)>=tyc_width||unsigned(y)>=tyc_height) return 0;
    const size_t i=size_t(y)*tyc_width+x;
    return tyc_map[i]>=0 ? tyc_pixels[i] : 0;
  }
  void setPixelColorXY(int x,int y,uint32_t color) {
    if (x<0||y<0||unsigned(x)>=tyc_width||unsigned(y)>=tyc_height) return;
    const size_t i=size_t(y)*tyc_width+x;
    if (tyc_map[i]>=0) tyc_pixels[i]=color;
  }
  void setPixelColor(int i,uint32_t color) {if(i>=0)setPixelColorXY(i%tyc_width,i/tyc_width,color);}
  void addPixelColorXY(int x,int y,uint32_t color) {setPixelColorXY(x,y,color_add(getPixelColorXY(x,y),color));}
  void fill(uint32_t color) {for(size_t i=0;i<tyc_pixels.size();++i)setPixelColor(int(i),color);}
  uint32_t color_from_palette(uint16_t index,bool mapping,bool wrap,uint8_t mcol,uint8_t brightness=255) const {
    if (!palette) throw std::runtime_error("palette zero requires an explicit color-gamma/video-scale model");
    if (mapping && tyc_pixels.size()>1) index=index*255/(tyc_pixels.size()-1);
    uint8_t slot=uint8_t(index);
    if (!wrap && paletteBlend!=3) slot=tyc_scale8(slot,240);
    return ColorFromPalette(tyc_palette,slot,brightness,paletteBlend==3?NOBLEND:LINEARBLEND);
  }
};
inline Segment tyc_segment;
struct TycStrip {
  uint32_t now=0;
  bool isMatrix=true;
  std::vector<void(*)()> effects;
  std::vector<std::string> names;
  unsigned getMappedPixelIndex(unsigned i) const {
    return i<tyc_map.size()&&tyc_map[i]>=0 ? unsigned(tyc_map[i]) : UINT32_MAX;
  }
  unsigned getLengthTotal() const {return tyc_physical;}
  void addEffect(unsigned,void(*fn)(),const char *data) {
    effects.push_back(fn);names.emplace_back(data);
  }
};
inline TycStrip strip;
struct TycAudioSlots {
  void *operator[](size_t index) const {
    if(index!=0)throw std::runtime_error("unsupported AudioReactive slot; only volumeSmth slot0 is modeled");
    return &tyc_volume;
  }
};
struct um_data_t {TycAudioSlots u_data;};
inline um_data_t tyc_audio{};
struct UsermodManager {
  static bool getUMData(um_data_t **data,int) {++tyc_audio_reads;*data=&tyc_audio;return true;}
};
inline um_data_t* simulateSound(uint8_t) {throw std::runtime_error("implicit simulated sound is disabled");}
struct Usermod {virtual void setup(){};virtual void loop(){};virtual uint16_t getId(){return 0;};virtual ~Usermod()=default;};
#define SEGMENT tyc_segment
#define SEGENV tyc_segment
#define SEGPALETTE tyc_palette
#define SEG_W tyc_width
#define SEG_H tyc_height
#define SEGLEN tyc_pixels.size()
#define SEGCOLOR(i) tyc_segment.colors.at(i)
