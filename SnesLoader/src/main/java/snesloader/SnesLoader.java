// SPDX-License-Identifier: MIT
// Originally by achan1989; expanded for headless / current Ghidra usage.
package snesloader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import snesloader.RomInfo.RomKind;

/**
 * Top-level Ghidra loader for Super Nintendo / Super Famicom ROMs.
 *
 * <p>Handles ROM kind detection (LoROM/HiROM, with or without an SMC copier
 * header), maps ROM banks into the 65816 24-bit bus space, and (optionally)
 * lays down WRAM, hardware-register, SRAM and interrupt-vector annotations
 * so that the program is immediately useful for analysis.</p>
 */
public class SnesLoader extends AbstractLibrarySupportLoader {

	public static final String LOADER_NAME = "SNES ROM";

	public static final String OPT_HW_REGS = "Map SNES hardware registers";
	public static final String OPT_VECTORS = "Mark interrupt vectors";
	public static final String OPT_HEADER_DT = "Apply Cartridge Header datatype";
	public static final String OPT_LOWRAM_MIRROR = "Map LowRAM mirror at $00:0000";
	public static final String OPT_SRAM = "Map cartridge SRAM (when present)";
	public static final String OPT_MSU1 = "Label MSU-1 streaming registers ($2000-$2007)";
	public static final String OPT_COPROC = "Label coprocessor registers (SA-1 / SuperFX / S-DD1)";
	public static final String OPT_MIRROR_HW_LABELS =
		"Mirror hardware-register labels into all banks $00-$3F and $80-$BF";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		if (detectRomKinds(provider).isEmpty()) {
			return loadSpecs;
		}
		// QueryOpinionService is the canonical way to look up languages declared in
		// `<processor>.opinion` files. It does the right thing without forcing the
		// 65816 processor to be registered ahead of time (Processor.toProcessor
		// throws a ProcessorNotFoundException for lazily-registered processors when
		// it's the first loader to run).
		List<QueryResult> results = QueryOpinionService.query(LOADER_NAME, null, null);
		if (results == null || results.isEmpty()) {
			return loadSpecs;
		}
		for (QueryResult r : results) {
			loadSpecs.add(new LoadSpec(this, 0, r));
		}
		return loadSpecs;
	}

	private static Collection<RomInfo> detectRomKinds(ByteProvider provider) {
		Collection<RomInfo> valid = new HashSet<>();
		for (RomKind kind : RomKind.values()) {
			for (boolean smc : new boolean[] { false, true }) {
				RomInfo r = new RomInfo(kind, smc);
				if (r.bytesLookValid(provider)) {
					valid.add(r);
				}
			}
		}
		return valid;
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws IOException {
		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();

		Collection<RomInfo> detected = detectRomKinds(provider);
		if (detected.isEmpty()) {
			throw new IOException("Not a valid SNES ROM (file changed since import?)");
		}
		RomInfo romInfo = pickBestMatch(detected, provider.length(), provider);
		if (romInfo == null) {
			StringBuilder sb = new StringBuilder("Cannot uniquely identify SNES ROM. Candidates:\n");
			for (RomInfo r : detected) {
				sb.append("  ").append(r.getDescription()).append('\n');
			}
			Msg.showError(this, null, "SNES Loader", sb.toString());
			throw new IOException(sb.toString());
		}

		// Re-parse with the chosen kind so the header is cached on the RomInfo.
		romInfo.bytesLookValid(provider);

		log.appendMsg(LOADER_NAME, "Loading " + romInfo.getDescription());
		if (romInfo.getHeader() != null) {
			log.appendMsg(LOADER_NAME, romInfo.getHeader().describe());
		}

		FlatProgramAPI fpa = new FlatProgramAPI(program, settings.monitor());

		// 1) Map ROM into the 65816 bus.
		boolean ok = romInfo.getLoader().load(provider, settings.loadSpec(), settings.options(),
				log, program, settings.monitor(), romInfo);
		if (!ok) {
			throw new IOException("ROM mapping failed");
		}

		// 2) Apply WRAM / hardware regs / SRAM / vectors / header DT, per options.
		SnesPostLoader.Options opts = parseOptions(settings.options());
		try {
			SnesPostLoader.apply(fpa, romInfo, opts, log);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram, mirrorFsLayout);

		list.add(new Option(OPT_HW_REGS, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesHwRegs"));
		list.add(new Option(OPT_VECTORS, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesVectors"));
		list.add(new Option(OPT_HEADER_DT, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesHeader"));
		list.add(new Option(OPT_LOWRAM_MIRROR, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesLowRamMirror"));
		list.add(new Option(OPT_SRAM, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesSram"));
		list.add(new Option(OPT_MSU1, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesMsu1"));
		list.add(new Option(OPT_COPROC, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesCoproc"));
		list.add(new Option(OPT_MIRROR_HW_LABELS, true, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-snesMirrorHwLabels"));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		String err = super.validateOptions(provider, loadSpec, options, program);
		if (err != null || options == null) {
			return err;
		}
		for (Option opt : options) {
			String n = opt.getName();
			if (OPT_HW_REGS.equals(n) || OPT_VECTORS.equals(n) || OPT_HEADER_DT.equals(n)
					|| OPT_LOWRAM_MIRROR.equals(n) || OPT_SRAM.equals(n)
					|| OPT_MSU1.equals(n) || OPT_COPROC.equals(n)
					|| OPT_MIRROR_HW_LABELS.equals(n)) {
				if (!Boolean.class.isAssignableFrom(opt.getValueClass())) {
					return "Invalid type for option: " + n + " - " + opt.getValueClass();
				}
			}
		}
		return null;
	}

	/**
	 * Score and pick the most plausible interpretation of a multi-candidate
	 * ROM. Both LoROM-at-$7FC0 and HiROM-at-$FFC0 can pass {@link
	 * RomInfo#bytesLookValid(ByteProvider)} on the same file by sheer
	 * coincidence: the heuristic only requires a checksum-complement pair
	 * plus a handful of plausible header bytes, and large cartridges have
	 * enough random data to satisfy that around either offset.
	 *
	 * <p>We resolve the tie with the following preferences, applied as a
	 * single additive score:
	 * <ul>
	 *   <li>Strongly prefer no-SMC over SMC-stripped (real cartridge dumps
	 *       almost always lack the 512-byte copier header today).</li>
	 *   <li>Strongly de-prefer LoROM when the file is larger than the
	 *       LoROM 4 MiB ceiling -- a 6 MiB "LoROM" detection is almost
	 *       always a $7FC0 coincidence on an SPC7110 / ExHiROM cartridge,
	 *       and picking it would silently truncate the upper 2 MiB of
	 *       game code.</li>
	 *   <li>As a final tie-break, prefer LoROM (the more common case for
	 *       small cartridges).</li>
	 * </ul></p>
	 */
	private static RomInfo pickBestMatch(Collection<RomInfo> candidates, long providerLen,
			ByteProvider provider) {
		if (candidates.size() == 1) {
			return candidates.iterator().next();
		}
		RomInfo best = null;
		int bestRank = Integer.MIN_VALUE;
		for (RomInfo r : candidates) {
			int rank = 0;
			rank += r.hasSmcHeader() ? 0 : 100;
			long romBytes = providerLen - r.getStartOffset();
			SnesHeader h = r.getHeader();
			boolean isExLoRom = h != null && h.isExLoRomMode();
			if (r.getKind() == RomKind.LO_ROM && romBytes > LoRomLoader.MAX_ROM_SIZE) {
				if (!isExLoRom) {
					rank -= 50;
				}
			}
			if (r.getKind() == RomKind.LO_ROM && !isExLoRom) {
				rank += 1;
			}
			// For ambiguous nibble-5 (ExLoROM/ExHiROM), use reset vector heuristic.
			if (isExLoRom) {
				int resetVec = h.getResetVector();
				if (r.getKind() == RomKind.LO_ROM) {
					long loRomOffset = r.getStartOffset() + resetVec - 0x8000L;
					try {
						if (loRomOffset + 1 < provider.length()) {
							byte b0 = provider.readByte((int) loRomOffset);
							if (b0 == (byte) 0xFF) {
								// LO_ROM mapping has no code at reset vector target.
								rank -= 300;
							}
						}
					} catch (IOException e) {
						// ignore
					}
				} else if (r.getKind() == RomKind.HI_ROM) {
					long hiRomOffset = r.getStartOffset() + (long) resetVec;
					try {
						if (hiRomOffset + 1 < provider.length()) {
							byte b0 = provider.readByte((int) hiRomOffset);
							if (b0 == (byte) 0xFF) {
								// HiROM mapping has no code at reset vector.
								rank -= 300;
							} else {
								// If both reset targets look populated, prefer the historical ExHiROM interpretation.
								rank += 1;
							}
						}
					} catch (IOException e) {
						// ignore
					}
				}
			}
			if (rank > bestRank) {
				bestRank = rank;
				best = r;
			}
		}
		return best;
	}

	private static SnesPostLoader.Options parseOptions(List<Option> options) {
		SnesPostLoader.Options o = new SnesPostLoader.Options();
		if (options == null) {
			return o;
		}
		for (Option opt : options) {
			Object v = opt.getValue();
			if (!(v instanceof Boolean)) {
				continue;
			}
			boolean b = (Boolean) v;
			switch (opt.getName()) {
				case OPT_HW_REGS:
					o.mapHwRegs = b;
					break;
				case OPT_VECTORS:
					o.markVectors = b;
					break;
				case OPT_HEADER_DT:
					o.applyHeaderDataType = b;
					break;
				case OPT_LOWRAM_MIRROR:
					o.mapLowRamMirror = b;
					break;
				case OPT_SRAM:
					o.mapSram = b;
					break;
				case OPT_MSU1:
					o.mapMsu1 = b;
					break;
				case OPT_COPROC:
					o.labelCoprocessor = b;
					break;
				case OPT_MIRROR_HW_LABELS:
					o.mirrorHwRegLabels = b;
					break;
				default:
					break;
			}
		}
		return o;
	}
}
