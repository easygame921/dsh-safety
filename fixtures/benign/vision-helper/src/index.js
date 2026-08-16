// Benign fixture: a plugin that calls a remote vision API (normal, legitimate).
// Network usage alone must NOT be a review finding (notice at most).
export const name = 'vision-helper';

export function apply(ctx) {
  ctx.tool('describe_image', async ({ imageUrl }) => {
    const response = await fetch('https://api.vision.example.com/v1/describe', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ imageUrl, model: 'glm-4.6v-flash' }),
    });
    const data = await response.json();
    return data.description;
  });
}
