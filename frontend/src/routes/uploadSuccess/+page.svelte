<script lang="ts">
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { CircleCheck, Copy, Check, ExternalLink, Upload } from '@lucide/svelte';

	type MediaKind = 'image' | 'video' | 'audio' | 'other';

	// This page is prerendered, so query params don't exist at build time
	// (SvelteKit throws if url.searchParams is read while prerendering).
	// Only read them once we're running in the browser.
	let mounted = $state(false);
	onMount(() => {
		mounted = true;
	});

	function param(...names: string[]): string {
		if (!mounted) return '';
		for (const name of names) {
			const value = page.url.searchParams.get(name);
			if (value) return value;
		}
		return '';
	}

	function isSafeUrl(value: string): boolean {
		try {
			const parsed = new URL(value, page.url.origin);
			return parsed.protocol === 'http:' || parsed.protocol === 'https:';
		} catch {
			return false;
		}
	}

	function mediaKind(value: string): MediaKind {
		let path = value;
		try {
			path = new URL(value, page.url.origin).pathname;
		} catch {
			// fall back to raw value
		}
		const ext = path.split('.').pop()?.toLowerCase() ?? '';
		if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'bmp'].includes(ext)) return 'image';
		if (['mp4', 'webm', 'mov', 'm4v', 'ogv'].includes(ext)) return 'video';
		if (['mp3', 'wav', 'ogg', 'm4a', 'flac', 'aac'].includes(ext)) return 'audio';
		return 'other';
	}

	// S3's success_action_redirect appends ?bucket=…&key=…&etag=… rather than a full URL,
	// so build the object URL from those when no explicit url param is given.
	const S3_REGION = 'eu-west-1';

	function s3ObjectUrl(bucket: string, key: string): string {
		if (!bucket || !key) return '';
		const path = key.split('/').map(encodeURIComponent).join('/');
		return `https://${bucket}.s3.${S3_REGION}.amazonaws.com/${path}`;
	}

	let rawUrl = $derived(
		param('url', 'media_url', 'mediaUrl') || s3ObjectUrl(param('bucket'), param('key'))
	);

	let mediaUrl = $derived(rawUrl && isSafeUrl(rawUrl) ? rawUrl : '');
	let kind = $derived<MediaKind>(mediaUrl ? mediaKind(mediaUrl) : 'other');

	// TODO: replace with a generated thumbnail once available; for now scale down the full image.
	let thumbnailUrl = $derived(kind === 'image' || kind === 'other' ? mediaUrl : '');

	let copied = $state<'url' | null>(null);

	async function copy(value: string, which: 'url') {
		try {
			await navigator.clipboard.writeText(value);
			copied = which;
			setTimeout(() => {
				if (copied === which) copied = null;
			}, 2000);
		} catch {
			// clipboard unavailable; ignore
		}
	}
</script>

<div class="mx-auto max-w-2xl py-8">
	<div class="flex items-center gap-3">
		<CircleCheck class="h-8 w-8 text-green-600" />
		<h1 class="text-3xl font-bold text-gray-900">Upload complete</h1>
	</div>
	<p class="mt-1 text-gray-600">Image upload processed successfully.</p>

	{#if !mounted}
		<!-- params are only available client-side; avoid flashing the warning -->
	{:else if !mediaUrl}
		<div class="mt-6 rounded-lg border border-yellow-200 bg-yellow-50 p-4 text-sm text-yellow-800">
			No media details were provided in the URL.
		</div>
	{:else}
		<div class="mt-6 space-y-6 rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
			{#if thumbnailUrl}
				<section>
					<h2 class="text-sm font-semibold text-gray-900">Thumbnail</h2>
					<img
						src={thumbnailUrl}
						alt="Thumbnail"
						class="mt-2 h-32 w-32 rounded-md border border-gray-200 object-cover"
					/>
				</section>
			{/if}

			<section>
				{@render urlRow('Media URL', mediaUrl, 'url')}
			</section>
		</div>
	{/if}

	<div class="mt-6 flex justify-end">
		<a
			href="/uploadImage"
			class="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700"
		>
			<Upload class="h-4 w-4" />
			Upload another
		</a>
	</div>
</div>

{#snippet urlRow(label: string, value: string, which: 'url')}
	<div>
		<label for="{which}-field" class="block text-sm font-medium text-gray-700">{label}</label>
		<div class="mt-1 flex gap-2">
			<input
				id="{which}-field"
				type="text"
				readonly
				{value}
				onfocus={(e) => e.currentTarget.select()}
				class="min-w-0 flex-1 rounded-md border border-gray-300 bg-gray-50 px-3 py-2 font-mono text-sm text-gray-800"
			/>
			<button
				type="button"
				onclick={() => copy(value, which)}
				aria-label="Copy {label}"
				class="cursor-pointer rounded-md border border-gray-300 px-3 py-2 text-gray-600 hover:bg-gray-50"
			>
				{#if copied === which}
					<Check class="h-4 w-4 text-green-600" />
				{:else}
					<Copy class="h-4 w-4" />
				{/if}
			</button>
			<a
				href={value}
				target="_blank"
				rel="noopener noreferrer"
				aria-label="Open {label}"
				class="rounded-md border border-gray-300 px-3 py-2 text-gray-600 hover:bg-gray-50"
			>
				<ExternalLink class="h-4 w-4" />
			</a>
		</div>
	</div>
{/snippet}
