import { defineCollection, z } from "astro:content";

const posts = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    date: z.union([z.string(), z.date()]),
    excerpt: z.string().optional(),
    header: z
      .object({
        teaser: z.string().optional()
      })
      .optional(),
    tags: z.array(z.string()).optional(),
    permalink: z.string().optional()
  })
});

export const collections = { posts };
