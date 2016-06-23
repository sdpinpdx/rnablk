#ifndef CONFIG_HAVE_DMA_ATTRS
struct dma_attrs;

#define dma_map_single_attrs(dev, cpu_addr, size, dir, attrs) \
        dma_map_single(dev, cpu_addr, size, dir)

#define dma_unmap_single_attrs(dev, dma_addr, size, dir, attrs) \
        dma_unmap_single(dev, dma_addr, size, dir)

#define dma_map_sg_attrs(dev, sgl, nents, dir, attrs) \
        dma_map_sg(dev, sgl, nents, dir)

#define dma_unmap_sg_attrs(dev, sgl, nents, dir, attrs) \
        dma_unmap_sg(dev, sgl, nents, dir)

#endif /* CONFIG_HAVE_DMA_ATTRS */
