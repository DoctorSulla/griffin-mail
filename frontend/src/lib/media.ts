import type { MediaObject } from '$lib/api';

const IMAGE_EXTENSION = /\.(png|jpe?g|gif|webp|avif|svg|bmp)$/i;

export function isImage(item: MediaObject): boolean {
	return IMAGE_EXTENSION.test(item.name);
}

export function sortNewestFirst(items: MediaObject[]): MediaObject[] {
	return items.toSorted(
		(a, b) => Date.parse(b.last_modified ?? '') - Date.parse(a.last_modified ?? '') || 0
	);
}

export function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDate(value: string): string {
	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString();
}

export function mediaDetails(item: MediaObject): string {
	return [
		item.size != null ? formatBytes(item.size) : '',
		item.last_modified ? formatDate(item.last_modified) : ''
	]
		.filter(Boolean)
		.join(' · ');
}
